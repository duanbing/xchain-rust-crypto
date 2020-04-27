extern crate ring;
use crate::keys::{PrivateKey, PublicKey};

use crate::errors::*;

fn derive_shared(pk: &PublicKey, sk_len: usize, mac_len: usize) -> Result<Vec<u8>> {
    Ok(vec![])
}

pub fn Encrypt(pk: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    Ok(vec![])
}

pub fn Decrypt(sk: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    Ok(vec![])
}
