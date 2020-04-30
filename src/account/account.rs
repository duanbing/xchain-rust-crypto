use crate::errors::{Error, ErrorKind, Result};
use crate::hdwallet::{rand, Language};
use crate::sign::ecdsa::KeyPair;
use num_traits::FromPrimitive;
use num_traits::Zero;
use std::ops::*;

pub struct ECDSAAccount {
    entropy: Vec<u8>,
    mnemonic: String,

    json_private_key: String,
    json_public_key: String,
    address: String,
}

pub fn generate_account_by_mnemonic(mnemonic: &String, lang: Language) -> Result<ECDSAAccount> {
    let cryptography = get_crypto_byte_from_mnemonic(mnemonic, lang)?;
    if cryptography != (super::address::CryptoType::NIST as u8) {
        return Err(Error::from(ErrorKind::ErrCryptographyNotSupported));
    }

    let password = "yes, you are handsome.".to_string();
    let seed_raw = rand::generate_seed_with_error_check(mnemonic, &password, 40, lang)?;

    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING;
    let seed = untrusted::Input::from(&seed_raw);
    let private_key = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, seed)?;

    // TO JSON
    // TODO 这里不符合规范，最好是pcks8格式
    let json_sk = super::json_key::get_ecdsa_private_key_json_format(&private_key)?;

    let json_pk = super::json_key::get_ecdsa_public_key_json_format(&private_key)?;

    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
    let public_key = crate::sign::ecdsa::UnparsedPublicKey::new(alg, private_key.public_key());
    let address = super::address::get_address_from_public_key(&public_key)?;

    Ok(ECDSAAccount {
        entropy: seed_raw,
        mnemonic: mnemonic.to_string(),
        json_public_key: json_pk,
        json_private_key: json_sk,
        address: address,
    })
}

pub fn get_crypto_byte_from_mnemonic(mnemonic: &String, lang: Language) -> Result<u8> {
    let entropy = rand::get_entropy_from_mnemonic(mnemonic, lang)?;
    //TODO 没有必要用到大整数计算
    let tag_byte = entropy[entropy.len() - 1]; // 8bits
    let err = Error::from(ErrorKind::InvalidBigNumError);
    let mut tag_int = num_bigint::BigInt::from_u8(tag_byte).ok_or(err)?;
    let err = Error::from(ErrorKind::InvalidBigNumError);
    let right_shift_4bits = num_bigint::BigInt::from_u32(16).ok_or(err)?;
    let err = Error::from(ErrorKind::InvalidBigNumError);
    let last_4bits_mask = num_bigint::BigInt::from_u32(15).ok_or(err)?;
    tag_int.div_assign(right_shift_4bits);

    let cryptography_int = tag_int.bitand(last_4bits_mask);
    if cryptography_int.is_zero() {
        return Err(Error::from(ErrorKind::ErrMnemonicNumNotValid));
    }
    Ok(cryptography_int.to_bytes_be().1[0])
}
