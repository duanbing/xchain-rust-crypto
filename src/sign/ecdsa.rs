use crate::{ec, errors::Result};

pub use crate::ec::suite_b::ecdsa::{
    signing::{EcdsaKeyPair, EcdsaSigningAlgorithm, ECDSA_P256_SHA256_ASN1_SIGNING},
    verification::{EcdsaVerificationAlgorithm, ECDSA_P256_SHA256_ASN1},
};

use core;
use untrusted;

pub fn sign_ecdsa_by_double_sha256(key_pair: &EcdsaKeyPair, msg: &[u8]) -> Result<Vec<u8>> {
    let msg = ring::digest::digest(&ring::digest::SHA256, msg);
    let sig = key_pair.sign(msg.as_ref())?;
    Ok(sig.as_ref().to_vec())
}

/// A signature verification algorithm.
pub trait VerificationAlgorithm: core::fmt::Debug + Sync {
    /// Verify the signature `signature` of message `msg` with the public key
    /// `public_key`.
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<()>;
}

/// A public key signature returned from a signing operation.
#[derive(Clone, Copy)]
pub struct Signature {
    value: [u8; MAX_LEN],
    len: usize,
}

pub(crate) const MAX_LEN: usize = 1/*tag:SEQUENCE*/ + 2/*len*/ +
    (2 * (1/*tag:INTEGER*/ + 1/*len*/ + 1/*zero*/ + ec::SCALAR_MAX_BYTES));

impl Signature {
    // Panics if `value` is too long.
    pub(crate) fn new<F>(fill: F) -> Self
    where
        F: FnOnce(&mut [u8; MAX_LEN]) -> usize,
    {
        let mut r = Self {
            value: [0; MAX_LEN],
            len: 0,
        };
        r.len = fill(&mut r.value);
        r
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.len]
    }
}
