// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) 2025 Tyler Fanelli
// Copyright (c) 2025 Sören Langenberg

use std::{
    collections::BTreeMap,
    fs::{read, write},
    io::{self},
    sync::{Mutex, RwLock},
};

use actix_web::{cookie::Cookie, post, web, App, HttpRequest, HttpResponse, HttpServer};
use aes::cipher::KeyInit;
use aes_gcm_siv::{
    aead::{Aead, Payload},
    Aes256GcmSiv, Nonce,
};
use base64::prelude::*;
use clap::Parser;
use cocoon_tpm_crypto::{
    ecc::{curve::Curve, ecdh::ecdh_c_1e_1s_cdh_party_u_key_gen, EccKey},
    hash::HmacInstance,
    rng::{self, HashDrbg, RngCore as _, X86RdSeedRng},
    CryptoError, EmptyCryptoIoSlices,
};
use cocoon_tpm_tpm2_interface::{
    self as tpm2_interface, Tpm2bEccParameter, TpmBuffer, TpmEccCurve, TpmiAlgHash, TpmsEccPoint,
};
use cocoon_tpm_utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon},
};
use kbs_types::{Challenge, ProtectedHeader, Request, Response, TeePubKey};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sev::firmware::guest::AttestationReport;
use uuid::Uuid;
use zerocopy::IntoBytes;

lazy_static! {
    pub static ref KEY: RwLock<
        Vec<(
            EccKey,
            TpmsEccPoint<'static>,
            Curve,
            rng::HashDrbg,
            Option<[u8; 32]>
        )>,
    > = RwLock::new(Vec::new());
    pub static ref SHARED_KEY: RwLock<Vec<Vec<u8>>> = RwLock::new(Vec::new());
    pub static ref MEASUREMENT: RwLock<Vec<u8>> = RwLock::new(Vec::new());
    pub static ref SECRET: RwLock<Vec<u8>> = RwLock::new(Vec::new());
    pub static ref NV: RwLock<Vec<String>> = RwLock::new(Vec::new());
    pub static ref ATTESTED: Mutex<bool> = Mutex::new(false);
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, short)]
    pub measurement: Option<String>,

    #[arg(long, short)]
    pub secret: Option<String>,

    #[arg(long = "path", short = 'p')]
    pub secret_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub success: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub algorithm: ResourceRequestHMAC,
    pub mac: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestResponse {
    pub pub_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ResourceRequestHMAC {
    HmacSha256,
    HmacSha512,
}

fn launch_measurement() -> Vec<u8> {
    MEASUREMENT.read().unwrap().clone()
}

fn secret() -> Result<Vec<u8>, anyhow::Error> {
    let mut secret = SECRET.read().unwrap().clone();
    if secret.is_empty() {
        secret = read(NV.read().unwrap().clone().last().unwrap()).expect("File read failed");
    }
    Ok(secret)
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.measurement.is_some() {
        let measurement = args.measurement.clone().unwrap();

        let mut bytes = BASE64_STANDARD.decode(measurement).unwrap();
        let mut m = MEASUREMENT.write().unwrap();
        m.append(&mut bytes);
    }

    if args.secret.is_some() {
        let secret = args.secret.clone().unwrap();

        let mut bytes = BASE64_STANDARD.decode(secret).unwrap();
        let mut s = SECRET.write().unwrap();
        s.append(&mut bytes);
    }

    if args.secret_path.is_some() {
        let secret_path = args.secret_path.clone().unwrap();

        let mut sp = NV.write().unwrap();
        sp.push(secret_path);
    }

    HttpServer::new(|| {
        App::new().service(
            web::scope("/kbs/v0")
                .service(auth)
                .service(attest)
                .service(syncback)
                .service(resource),
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[post("/auth")]
pub async fn auth(_req: web::Json<Request>) -> HttpResponse {
    let cookie = Cookie::build("kbs-session-id", Uuid::new_v4().to_string()).finish();

    let c = Challenge {
        nonce: BASE64_STANDARD.encode(Uuid::new_v4().as_bytes()),
        extra_params: Value::String(String::new()),
    };

    HttpResponse::Ok().cookie(cookie).json(c)
}

/// Placeholder for attesting a client's TEE evidence.
#[post("/attest")]
pub async fn attest(req: HttpRequest, attest: web::Json<kbs_types::Attestation>) -> HttpResponse {
    let _cookie = req.cookie("kbs-session-id").unwrap();

    let attest = attest.into_inner();

    let serde_json::Value::String(tee_evidence) = attest.tee_evidence else {
        panic!("evidence not a base64 string");
    };

    let evidence = BASE64_URL_SAFE.decode(&tee_evidence).unwrap();

    let report: AttestationReport = unsafe { std::ptr::read(evidence.as_ptr() as *const _) };

    if report.measurement.as_ref() == launch_measurement() {
        let mut val = ATTESTED.lock().unwrap();
        *val = true;
    } else {
        println!(
            "\nlaunch measurement not as expected\nexpected:{:?}\nfound:{:?}",
            BASE64_STANDARD.encode(launch_measurement()),
            BASE64_STANDARD.encode(report.measurement.as_ref())
        );
    }

    let ec = match attest.tee_pubkey {
        TeePubKey::EC {
            crv: _,
            alg: _,
            x,
            y,
        } => {
            let curve = Curve::new(TpmEccCurve::NistP384).unwrap();

            let x = BASE64_URL_SAFE.decode(x).unwrap();
            let y = BASE64_URL_SAFE.decode(y).unwrap();

            let point = TpmsEccPoint {
                x: Tpm2bEccParameter {
                    buffer: TpmBuffer::Owned(x),
                },
                y: Tpm2bEccParameter {
                    buffer: TpmBuffer::Owned(y),
                },
            };
            let mut rng = {
                let mut rdseed = X86RdSeedRng::instantiate().unwrap();
                let mut hash_drbg_entropy =
                    try_alloc_zeroizing_vec(HashDrbg::min_seed_entropy_len(TpmiAlgHash::Sha256))
                        .unwrap();

                rdseed
                    .generate::<_, EmptyCryptoIoSlices>(
                        io_slices::SingletonIoSliceMut::new(hash_drbg_entropy.as_mut_slice())
                            .map_infallible_err(),
                        None,
                    )
                    .unwrap();

                rng::HashDrbg::instantiate(
                    tpm2_interface::TpmiAlgHash::Sha256,
                    &hash_drbg_entropy,
                    None,
                    Some(b"SVSM attestation RNG"),
                )
            }
            .unwrap();

            let curve_ops = curve.curve_ops().unwrap();

            let ecc = EccKey::generate(&curve_ops, &mut rng, None).unwrap();

            (ecc, point, curve, rng)
        }
        _ => panic!("invalid RSA key"),
    };

    {
        let mut key = KEY.write().unwrap();
        let mut id = [0u8; 32];
        id[..16].copy_from_slice(report.family_id.as_ref());
        id[16..].copy_from_slice(report.image_id.as_ref());
        key.push((ec.0, ec.1, ec.2, ec.3, Some(id)));
    }

    // Generate PubKey of KBS
    let (_, public, _curve, mut rng, _) = {
        let mut vec = KEY.write().unwrap();
        vec.pop().unwrap()
    };

    let (shared_secret, pub_key_u_plain) = ecdh_c_1e_1s_cdh_party_u_key_gen(
        TpmiAlgHash::Sha256,
        "",
        TpmEccCurve::NistP384,
        &public,
        &mut rng,
        None,
    )
    .unwrap();

    {
        let mut tmp = SHARED_KEY.write().unwrap();
        tmp.push(shared_secret.clone().to_vec());
    }

    let ec = serde_json::json!({
        "x_b64url": BASE64_URL_SAFE.encode(&*pub_key_u_plain.x.buffer),
        "y_b64url": BASE64_URL_SAFE.encode(&*pub_key_u_plain.y.buffer),
    });

    let resp = AttestResponse {
        pub_key: serde_json::to_vec(&ec).unwrap(),
    };

    HttpResponse::Ok().json(resp)
}

// n.b. The IDS are currently not utilized for identifiyng a VM and releasing the correct secret
#[post("/{resouce_id}")]
pub async fn resource(
    _req: HttpRequest,
    resource_id: web::Path<String>,
    resource: web::Json<ResourceRequest>,
) -> HttpResponse {
    let id = resource_id.into_inner();
    if id != "svsm_secret" {
        panic!("invalid resource id");
    }

    let attested = ATTESTED.lock().unwrap();
    if !*attested {
        println!("client is unattested, not releasing secret");
        return HttpResponse::Forbidden().into();
    }

    let material = {
        let vec = SHARED_KEY.read().unwrap();
        vec.last().unwrap().clone()
    };

    let res_request = resource.into_inner();
    let mut input = [0u8; 32];
    input[..16].copy_from_slice(&res_request.family_id);
    input[16..].copy_from_slice(&res_request.image_id);

    match res_request.algorithm {
        ResourceRequestHMAC::HmacSha256 => {
            let mut hmac = HmacInstance::new(TpmiAlgHash::Sha256, &material[..])
                .expect("HMAC is able to accept all key sizes");

            hmac.update(io_slices::GenericIoSlicesIter::new(
                [Some(input.as_bytes())]
                    .iter()
                    .map(|opt| opt.ok_or(CryptoError::Internal)),
                None,
            ))
            .expect("HMAC update error");

            let mut mac = [0u8; 32];
            hmac.finalize_into(&mut mac)
                .expect("HMAC finalize_into is infallible and can not fail");

            if mac.to_vec() != res_request.mac {
                println!("MAC mismatch!");
            }
        }
        ResourceRequestHMAC::HmacSha512 => {
            let mut hmac = HmacInstance::new(TpmiAlgHash::Sha512, &material[..])
                .expect("HMAC is able to accept all key sizes");

            hmac.update(io_slices::GenericIoSlicesIter::new(
                [Some(input.as_bytes())]
                    .iter()
                    .map(|opt| opt.ok_or(CryptoError::Internal)),
                None,
            ))
            .expect("HMAC update error");

            let mut mac = [0u8; 32];
            hmac.finalize_into(&mut mac)
                .expect("HMAC finalize_into is infallible and can not fail");

            if mac.to_vec() != res_request.mac {
                println!("MAC mismatch!");
            }
        }
    }

    let aes = Aes256GcmSiv::new_from_slice(&material[..]).unwrap();

    let mut rdseed = X86RdSeedRng::instantiate().expect("Error during seed setup");
    let mut hash_drbg_entropy = try_alloc_zeroizing_vec(12).expect("Error during vec alloc");

    rdseed
        .generate::<_, EmptyCryptoIoSlices>(
            io_slices::SingletonIoSliceMut::new(hash_drbg_entropy.as_mut_slice())
                .map_infallible_err(),
            None,
        )
        .expect("Error during RNG creation");

    let nonce = Nonce::from_slice(&hash_drbg_entropy);

    let encrypted_secret = match aes.encrypt(nonce, secret().unwrap().as_ref()) {
        Ok(val) => val,
        Err(_err) => panic!("Encryption failed"),
    };

    let protected = ProtectedHeader {
        alg: "ECDHP384".to_string(),
        enc: "AES128".to_string(),
        other_fields: BTreeMap::new(),
    };

    let resp = Response {
        protected,
        encrypted_key: "".to_string().into(),
        aad: None,
        iv: nonce.to_vec(),
        ciphertext: encrypted_secret,
        tag: "".to_string().into(),
    };

    HttpResponse::Ok().json(resp)
}

#[post("/syncback")]
pub async fn syncback(_req: HttpRequest, secret: web::Json<SyncRequest>) -> HttpResponse {
    let request = secret.into_inner();

    let material = {
        let vec = SHARED_KEY.read().unwrap();
        vec.last().unwrap().clone()
    };

    let path = {
        let vec = NV.write().unwrap();
        vec.last().unwrap().clone()
    };

    let iv = request.nonce;
    let enc = request.secret;
    let family_id = request.family_id;
    let image_id = request.image_id;

    let mut aad = [0u8; 32];
    aad[..16].copy_from_slice(&family_id);
    aad[16..].copy_from_slice(&image_id);

    let aes = Aes256GcmSiv::new_from_slice(&material).unwrap();
    let nonce = Nonce::from_slice(iv.as_slice());

    let payload = Payload {
        msg: enc.as_slice(),
        aad: &aad,
    };

    let decrypted = aes.decrypt(nonce, payload).unwrap();

    write(path, decrypted).expect("Failed to write");

    let resp = SyncResponse { success: true };

    HttpResponse::Ok().json(resp)
}
