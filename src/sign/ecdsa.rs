use crate::errors::Result;
use crate::keys::PrivateKey;

pub fn sign_ecdsa_by_double_sha256(key_pair: &PrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    let msg = ring::digest::digest(&ring::digest::SHA256, msg);
    key_pair.sign(msg.as_ref())
}
