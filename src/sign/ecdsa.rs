use crate::{ec, errors::Result};

pub use crate::ec::suite_b::ecdsa::{
    signing::{EcdsaKeyPair, EcdsaSigningAlgorithm, ECDSA_P256_SHA256_ASN1_SIGNING},
    verification::{EcdsaVerificationAlgorithm, ECDSA_P256_SHA256_ASN1},
};

use core;
use untrusted;

/*
pub fn sign_ecdsa_by_double_sha256(key_pair: &EcdsaKeyPair, msg: &[u8]) -> Result<Vec<u8>> {
    let msg = ring::digest::digest(&ring::digest::SHA256, msg);
    let sig = key_pair.sign(msg.as_ref())?;
    Ok(sig.as_ref().to_vec())
}
*/

/// Key pairs for signing messages (private key and public key).
pub trait KeyPair: core::fmt::Debug + Send + Sized + Sync {
    /// The type of the public key.
    type PublicKey: AsRef<[u8]> + core::fmt::Debug + Clone + Send + Sized + Sync;

    /// The public key for the key pair.
    fn public_key(&self) -> &Self::PublicKey;
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

/// An unparsed, possibly malformed, public key for signature verification.
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    algorithm: &'static dyn VerificationAlgorithm,
    bytes: B,
}

impl<B: Copy> Copy for UnparsedPublicKey<B> where B: AsRef<[u8]> {}

impl<B: Clone> Clone for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            bytes: self.bytes.clone(),
        }
    }
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    /// Construct a new `UnparsedPublicKey`.
    ///
    /// No validation of `bytes` is done until `verify()` is called.
    #[inline]
    pub fn new(algorithm: &'static dyn VerificationAlgorithm, bytes: B) -> Self {
        Self { algorithm, bytes }
    }

    /// Parses the public key and verifies `signature` is a valid signature of
    /// `message` using it.
    ///
    /// See the [crate::signature] module-level documentation for examples.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.algorithm.verify(
            untrusted::Input::from(self.bytes.as_ref()),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        )
    }

    pub fn xy(&self) -> (&[u8], &[u8]) {
        let t = self.bytes.as_ref();
        let elem_and_scalar_bytes: usize = (t.len() - 1) / 2;
        (&t[1..]).split_at(elem_and_scalar_bytes)
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for UnparsedPublicKey<B> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_ref()
    }
}

/// The maximum length, in bytes, of an encoded public key.

#[cfg(test)]
mod tests {

    use rand::Rng;

    use super::*;
    use crate::sign::ecdsa::KeyPair;
    use std::str::FromStr;
    extern crate hex;

    #[test]
    pub fn test_seed_private_public() {
        //let d = "29079635126530934056640915735344231956621504557963207107451663058887647996601";
        //let seed_bytes = num_bigint::BigInt::from_str(&d).unwrap().to_bytes_be();
        let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING;
        //let seed = untrusted::Input::from(&seed_bytes.1);
        //let private_key = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, seed);
        let mut r = vec![0u8; 32];
        rand::thread_rng().fill(&mut r[..]);
        let private_key =
            crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, untrusted::Input::from(&r));

        assert_eq!(private_key.is_ok(), true);
        let private_key = private_key.unwrap();
        //let msg = "hello, bing!";
        let msg = base64::decode("3LpLPx65qASpJmeFB+bjFBV+W+z6NK8GcQl0E2knd7w=").unwrap();
        let sig = private_key.sign(&msg);
        assert_eq!(sig.is_ok(), true);
        let sig = sig.unwrap();
        let sig64 = base64::encode(sig);
        println!("sig: {:?}", sig64);

        let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        println!(
            "public key: {:?}, \nhex={:?}",
            private_key.public_key().as_ref(),
            hex::encode(private_key.public_key().as_ref())
        );

        let public_key = self::UnparsedPublicKey::new(alg, private_key.public_key());
        let res = public_key.verify(&msg, sig.as_ref());
        assert_eq!(true, res.is_ok());
    }

    #[test]
    pub fn test_public_sig() {
        let key_slice = hex::decode(
        "04a664e9bbf6d03e4b75758f7ee3732a0a8eff9e76a0edc9a14ca584b966493664d0d8b7871c5b33bdee9f0e154d7eb948356229e7694cb04a785520952dae1438",
    )
    .unwrap();

        let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = self::UnparsedPublicKey::new(alg, &key_slice);
        let msg = String::from("hello world");
        let sig = hex::decode("3046022100873aad44cea8badf28c8f6b4509763e875a21805daf971bffc3a9bd27288a30b022100899216a47e3f071ede3d697bb172b94a9240d0c8cc6a5754a68edc00e1752873").unwrap();
        let res = public_key.verify(&msg.as_bytes(), &sig);
        println!("{:?}", res);
    }

    #[test]
    pub fn test_sign() {
        let key_slice = hex::decode(
            "04a24cf1352cd8d21be0567ce730cc9a78f5269d2eeabc44e5cb7aa01cd76ac50c0157f847b864048021d9116dc799b1c4659aeffb5606c4b28801b287eb709de8",
        ).unwrap();
        let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = self::UnparsedPublicKey::new(alg, &key_slice);
        let msg = base64::decode("3LpLPx65qASpJmeFB+bjFBV+W+z6NK8GcQl0E2knd7w=").unwrap();
        //let sig = base64::decode("MEUCIQD2GstVJp38SLDDHQbcrGeGUANsxNfVSZVhujByrQTLqwIgBdKLgc8Hfr3zibQ8wj3aixEs2qwGkzcdOXOpRoTAUyk=").unwrap();
        let sig = base64::decode("MEYCIQDT5btCwDOqc9dNpgP8yU/W7fxhs1TVruJCzmbmVTpGXQIhAITc/5PKxEWcY8E8iCtduEAM/Cz14HMPpyjwggah/Bv3").unwrap();
        let res = public_key.verify(&msg, &sig);
        println!("{:?}", res);
    }
}
