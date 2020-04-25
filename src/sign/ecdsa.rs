use crate::errors::Result;

pub fn sign_ecdsa_by_double_sha256(
    key_pair: &ring::signature::EcdsaKeyPair,
    msg: &[u8],
) -> Result<Vec<u8>> {
    let msg = ring::digest::digest(&ring::digest::SHA256, msg);
    let r = ring::rand::SystemRandom::new();
    let sig = key_pair.sign(&r, msg.as_ref()).unwrap();
    Ok(sig.as_ref().to_vec())
}
