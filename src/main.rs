// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) 2024 Tyler Fanelli
// Copyright (c) 2025 Sören Langenberg

use std::{io, sync::RwLock, fs::read};

use actix_web::{cookie::Cookie, post, web, App, HttpRequest, HttpResponse, HttpServer};
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    aead::rand_core::RngCore,
    Aes256GcmSiv, Nonce
};

use base64::prelude::*;
use kbs_types::{Challenge, Request, Response, TeePubKey};
use lazy_static::lazy_static;
use openssl::{
    bn::BigNum,
    pkey::Public,
    rsa::{Padding, Rsa},
};
use serde_json::Value;
use uuid::Uuid;
use clap::Parser;

lazy_static! {
    pub static ref KEY: RwLock<Vec<Rsa<Public>>> = RwLock::new(Vec::new());
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    // Local filesystem path to the NVChip of the generated TPM
    #[clap(long = "path")]
    tpm_path: String,
}

lazy_static!{
    pub static ref NV: RwLock<Vec<String>> = RwLock::new(Vec::new());
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    let mut tmp = NV.write().unwrap();
    tmp.push(args.tpm_path);

    HttpServer::new(|| {
        App::new().service(
            web::scope("/kbs/v0")
                .service(auth)
                .service(attest)
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
    let cookie = req.cookie("kbs-session-id").unwrap();

    println!("session ID: {}", cookie.value());

    let attest = attest.into_inner();

    let rsa = match attest.tee_pubkey {
        TeePubKey::RSA {
            alg: _,
            k_mod,
            k_exp,
        } => {
            let n_bytes = BASE64_URL_SAFE.decode(&k_mod).unwrap();
            let e_bytes = BASE64_URL_SAFE.decode(&k_exp).unwrap();

            let n = BigNum::from_slice(&n_bytes).unwrap();
            let e = BigNum::from_slice(&e_bytes).unwrap();

            Rsa::from_public_components(n, e).unwrap()
        }
        _ => panic!("invalid RSA key"),
    };

    let mut key = KEY.write().unwrap();
    key.push(rsa);

    let resp = Response {
        protected: "".to_string(),
        encrypted_key: "".to_string(),
        iv: "".to_string(),
        ciphertext: "".to_string(),
        tag: "".to_string(),
    };

    HttpResponse::Ok().json(resp)
}

#[post("/{resouce_id}")]
pub async fn resource(_req: HttpRequest, resource_id: web::Path<String>) -> HttpResponse {
    let id = resource_id.into_inner();
    if id != "svsm_secret" {
        panic!("invalid resource id");
    }

    let key = {
        let mut vec = KEY.write().unwrap();
        vec.pop().unwrap()
    };

    // Aes initialization
    let aes_key = Aes256GcmSiv::generate_key(&mut OsRng);
    let cipher = Aes256GcmSiv::new(&aes_key);
    let mut rand = [0u8; 12];
    OsRng.fill_bytes(&mut rand);
    let nonce = Nonce::from_slice(&rand);

    println!("Aes Key generated");

    let path = {
        let vec = NV.write().unwrap();
        vec.last().unwrap().clone()
    };

    let secret = read(path).expect("Nothing");
    println!("vTPM read");
    let encrypted_secret = match cipher.encrypt(nonce, secret.as_ref()) {
        Ok(value) => value, Err(_err) => panic!("Encryption failed")
    };

    println!("vTPM encrypted");

    let mut buf = vec![0; key.size() as usize];
    let len = key
        .public_encrypt(aes_key.as_ref(), &mut buf, Padding::PKCS1)
        .unwrap();
    println!("AES Key encrypted");

    let encrypted_aes_key = BASE64_STANDARD.encode(&buf[..len]);
    let encrypted_secret_encoded = BASE64_STANDARD.encode(encrypted_secret);
    let nonce_encoded = BASE64_STANDARD.encode(&nonce);

    println!("Everything encoded");


    let resp = Response {
        protected: "".to_string(),
        encrypted_key: encrypted_aes_key,
        iv: nonce_encoded,
        ciphertext: encrypted_secret_encoded,
        tag: "".to_string(),
    };

    HttpResponse::Ok().json(resp)
}
