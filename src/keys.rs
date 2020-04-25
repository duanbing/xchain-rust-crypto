extern crate base58;
extern crate num_bigint;
extern crate ring;
use crate::errors::{Error, ErrorKind, Result};

const PUBLIC_KEY_MAX_LEN: usize = 65;

//#[derive(PartialEq)]
//enum CryptoVersion {
//    NIST,
//    GM,
//}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum AlgorithmID {
    ECDSA_P256_SHA256_ASN1,
}

pub struct PublicKey {
    pub alg: AlgorithmID,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    pub key_buf: Vec<u8>,
}

impl PublicKey {
    pub fn new(pubk: &[u8]) -> Self {
        assert_eq!(pubk.len(), PUBLIC_KEY_MAX_LEN);
        let x = unsafe { std::slice::from_raw_parts(&(pubk[1]), 32) };
        let y = unsafe { std::slice::from_raw_parts(&(pubk[33]), 32) };
        PublicKey {
            alg: AlgorithmID::ECDSA_P256_SHA256_ASN1,
            x: x.to_vec().into(),
            y: y.to_vec().into(),
            key_buf: pubk.to_vec().into(),
        }
    }

    pub fn verify(&self, sig: &[u8], msg: &[u8]) -> Result<()> {
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &self.key_buf,
        );
        match public_key.verify(msg, sig) {
            Ok(x) => Ok(x),
            Err(e) => {
                println!("verify: {:?}", e);
                return Err(Error::from(ErrorKind::CryptoError));
            }
        }
    }
}

pub struct PrivateKey {
    pub doc: Vec<u8>,
    pub pubk: PublicKey,
}

impl PrivateKey {
    pub fn new(&self) -> Self {
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let r = &ring::rand::SystemRandom::new();
        let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, r).unwrap();
        let sk = ring::signature::EcdsaKeyPair::from_pkcs8(alg, &doc.as_ref()).unwrap();
        let pk = ring::signature::KeyPair::public_key(&sk);
        PrivateKey {
            doc: doc.as_ref().to_vec(),
            pubk: PublicKey::new(pk.as_ref()),
        }
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Self {
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let sk = ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8).unwrap();
        let pk = ring::signature::KeyPair::public_key(&sk);
        PrivateKey {
            doc: pkcs8.to_vec().into(),
            pubk: PublicKey::new(pk.as_ref()),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let sk = ring::signature::EcdsaKeyPair::from_pkcs8(alg, &self.doc).unwrap();
        let r = &ring::rand::SystemRandom::new();
        let res = sk.sign(r, msg).unwrap();
        Ok(res.as_ref().to_vec())
    }
}
