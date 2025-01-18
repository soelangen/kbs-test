// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) 2024 Tyler Fanelli
// Copyright (c) 2025 Sören Langenberg

use std::{collections::BTreeMap, fs::read, fs::write, io, sync::RwLock};

use actix_web::{cookie::Cookie, post, web, App, HttpRequest, HttpResponse, HttpServer};
use aes_gcm_siv::{
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use base64::prelude::*;
use elliptic_curve::JwkEcKey;
use kbs_types::{Challenge, ProtectedHeader, Request, Response, TeePubKey};
use lazy_static::lazy_static;
use p384::{ecdh::EphemeralSecret, EncodedPoint, NistP384};
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    // Local filesystem path to the NVChip of the generated TPM
    #[clap(long = "path")]
    tpm_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub success: bool,
}

lazy_static! {
    pub static ref KEY: RwLock<Vec<(JwkEcKey, EphemeralSecret)>> = RwLock::new(Vec::new());
}

lazy_static! {
    pub static ref NV: RwLock<Vec<String>> = RwLock::new(Vec::new());
}

lazy_static! {
    pub static ref AES_MATERIAL: RwLock<Vec<Vec<u8>>> = RwLock::new(Vec::new());
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    {
        let mut tmp = NV.write().unwrap();
        tmp.push(args.tpm_path);
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

    let ec = match attest.tee_pubkey {
        TeePubKey::EC {
            crv: _,
            alg: _,
            x,
            y,
        } => {
            let x = BASE64_URL_SAFE.decode(x).unwrap();
            let y = BASE64_URL_SAFE.decode(y).unwrap();

            let epoint = EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            let jwk = JwkEcKey::from_encoded_point::<NistP384>(&epoint).unwrap();
            let private = EphemeralSecret::random(&mut OsRng);

            (jwk, private)
        }
        _ => panic!("invalid RSA key"),
    };

    let mut key = KEY.write().unwrap();
    key.push(ec);

    HttpResponse::Ok().into()
}

#[post("/{resouce_id}")]
pub async fn resource(_req: HttpRequest, resource_id: web::Path<String>) -> HttpResponse {
    let id = resource_id.into_inner();
    if id != "svsm_secret" {
        panic!("invalid resource id");
    }

    let (jwk, private) = {
        let mut vec = KEY.write().unwrap();
        vec.pop().unwrap()
    };

    let public = jwk.to_public_key().unwrap();
    let shared = private.diffie_hellman(&public);
    let hkdf = shared.extract::<Sha256>(None);

    let mut out = [0u8; 32];
    let empty: [u8; 0] = [];

    hkdf.expand(&empty, &mut out).unwrap();
    {
        let mut tmp = AES_MATERIAL.write().unwrap();
        tmp.push(Vec::from(out.clone()));
    }

    let aes = Aes256GcmSiv::new_from_slice(&out).unwrap();

    let mut rand = [0u8; 12];
    OsRng.fill_bytes(&mut rand);
    let nonce = Nonce::from_slice(&rand);

    let path = {
        let vec = NV.write().unwrap();
        vec.last().unwrap().clone()
    };

    let plaintext = read(path).expect("Nothing");

    let encrypted_secret = match aes.encrypt(nonce, plaintext.as_ref()) {
        Ok(value) => value,
        Err(_err) => panic!("Encryption failed"),
    };

    let protected = ProtectedHeader {
        alg: "ECDHP384".to_string(),
        enc: "AES128".to_string(),
        other_fields: BTreeMap::new(),
    };

    let resp = Response {
        protected,
        encrypted_key: private.public_key().to_sec1_bytes().to_vec(),
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
        let vec = AES_MATERIAL.read().unwrap();
        vec.last().unwrap().clone()
    };

    let path = {
        let vec = NV.write().unwrap();
        vec.last().unwrap().clone()
    };

    let iv = request.nonce;
    let enc = request.secret;

    let aes = Aes256GcmSiv::new_from_slice(&material).unwrap();
    let nonce = Nonce::from_slice(iv.as_slice());

    let decrypted = aes.decrypt(nonce, enc.as_slice()).unwrap();

    write(path, decrypted).expect("Failed to write");

    let resp = SyncResponse { success: true };

    HttpResponse::Ok().json(resp)
}
