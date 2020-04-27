use crate::ec::keys::PublicKey;
use crate::errors::{Error, ErrorKind, Result};
use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;

use base58::{FromBase58, ToBase58};
use ring::digest;
use std::collections::HashMap;

pub enum CryptoType {
    NIST = 1,
    GM = 2,
}

pub fn get_address_from_public_keys(keys: &[PublicKey]) -> Result<String> {
    let mut pubk_map = HashMap::new();
    for key in keys.iter() {
        pubk_map.insert(&key.x, &key.y);
    }
    let res = serde_json::to_vec(&pubk_map)?;
    get_address_from_key_data(&keys[0], &res)
}

fn get_address_from_key_data(_key: &PublicKey, data: &[u8]) -> Result<String> {
    let hash256 = digest::digest(&digest::SHA256, data);
    let mut ha = Ripemd160::new();
    let mut hash160 = vec![0u8; 20];
    ha.input(&mut hash256.as_ref());

    //TODO:  NIST only now, get the standard from _key
    let n_version = CryptoType::NIST as u8;
    let mut buf = vec![n_version; 1];
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
