extern crate base58;
extern crate num_bigint;
extern crate ring;
use crate::errors::{Error, ErrorKind, Result};

use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;

use base58::{FromBase58, ToBase58};
use ring::digest;
//use ring::signature::UnparsedPublicKey;
use std::collections::HashMap;
use std::vec::Vec;

const PUBLIC_KEY_MAX_LEN: usize = 65;

//#[derive(PartialEq)]
//enum CryptoVersion {
//    NIST,
//    GM,
//}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
enum AlgorithmID {
    ECDSA_P256_SHA256_ASN1,
}

pub struct PublicKey {
    alg: AlgorithmID,
    x: Vec<u8>,
    y: Vec<u8>,
    key_buf: Vec<u8>,
}

impl PublicKey {
    pub fn new(&self, pubk: &[u8]) -> Self {
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

    pub fn sign(&self, sig: &[u8], msg: &[u8]) -> Result<()> {
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

/*
impl PrivateKey {
    pub fn new(&self, seed: &[u8]) -> Self {
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let doc = match ring::signature::EcdsaKeyPair::generate_pkcs8(alg, seed) {
            Ok(x) => x,
            Err(e) => return PrivateKey { is_valid: false },
        };
        let k = ring::signature::EcdsaKeyPair::from_pkcs8(alg, doc);
    }
}
*/
pub fn get_address_from_public_keys(keys: &[PublicKey]) -> Result<String> {
    check_pubk_in_one_curve(keys)?;
    let mut pubk_map = HashMap::new();
    for key in keys.iter() {
        pubk_map.insert(&key.x, &key.y);
    }
    let res = serde_json::to_vec(&pubk_map)?;
    get_address_from_key_data(&keys[0], &res)
}

fn check_pubk_in_one_curve(keys: &[PublicKey]) -> Result<()> {
    let key1 = &keys[0];
    for key in keys.iter() {
        if key.alg != key1.alg {
            return Err(Error::from(ErrorKind::NotExactTheSameCurveInputError));
        }
    }
    Ok(())
}

fn get_address_from_key_data(_key: &PublicKey, data: &[u8]) -> Result<String> {
    let hash256 = digest::digest(&digest::SHA256, data);
    let mut ha = Ripemd160::new();
    let mut hash160 = vec![0u8; 20];
    ha.input(&mut hash256.as_ref());

    //TODO:  NIST only now, get the standard from _key
    let mut buf = vec![1u8; 1];
    buf.append(&mut hash160);

    let check_code = crate::hash::hash::double_sha256(&buf);
    let mut check_code_4 = vec![0u8; 4];
    check_code_4.copy_from_slice(&check_code[0..4]);
    buf.append(&mut check_code_4);
    Ok(buf.to_base58())
}

pub fn verify_address_using_public_keys(address: &String, pubks: &[PublicKey]) -> Result<u8> {
    let slice = match address.from_base58() {
        Ok(x) => x,
        Err(e) => {
            println!("{:?}", e);
            return Err(Error::from(ErrorKind::ParseError));
        }
    };

    let res = get_address_from_public_keys(pubks)?;
    if &res != address {
        return Err(Error::from(ErrorKind::InvalidAddressError));
    }
    Ok(slice[0])
}

pub fn check_address_format(address: &String) -> Result<u8> {
    let slice = match address.from_base58() {
        Ok(x) => x,
        Err(e) => {
            println!("{:?}", e);
            return Err(Error::from(ErrorKind::ParseError));
        }
    };
    let check_code = &slice[(slice.len() - 4)..];
    let n_version = slice[0];
    let buf = &slice[1..slice.len() - 4];
    let check_code_in = crate::hash::hash::double_sha256(&buf);
    if check_code.to_vec() != check_code_in {
        return Err(Error::from(ErrorKind::InvalidAddressError));
    }
    Ok(n_version)
}
