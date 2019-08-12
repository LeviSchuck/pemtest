extern crate pem;

use pem::parse;
use ring::{rand, signature};
use ring::signature::KeyPair;

// Created with openssl genrsa -out private.pem 2048
const PRIVATE_KEY: &'static str = include_str!("private.pem");

fn sign_and_verify_rsa() -> Result<(), MyError> {
    // Create an `RsaKeyPair` from the DER-encoded bytes. This example uses
    // a 2048-bit key, but larger keys are also supported.
    let private_key_content = parse(PRIVATE_KEY).unwrap();

    let key_pair = signature::RsaKeyPair::from_der(&private_key_content.contents)
        .map_err(|e| {
            println!("{}", e);
            MyError::BadPrivateKey
        }).unwrap();

    // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
    // SHA256 digest algorithm.
    const MESSAGE: &'static [u8] = b"hello, world";
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public_modulus_len()];
    key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE, &mut signature)
        .map_err(|_| MyError::OOM)?;

    // Verify the signature.
    let public_key =
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,
                                        key_pair.public_key().as_ref());
    let result = public_key.verify(MESSAGE, &signature)
        .map_err(|e| {
            println!("{}", e);
            MyError::BadSignature
        });
    println!("Successfully signed and verified signature");
    result
}

#[derive(Debug)]
enum MyError {
   BadPrivateKey,
   OOM,
   BadSignature,
}

fn main() {
    sign_and_verify_rsa().unwrap();   
}
