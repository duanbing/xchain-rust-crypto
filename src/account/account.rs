use crate::errors::{Error, ErrorKind, Result};
use crate::hdwallet::{rand, Language};
use num_traits::FromPrimitive;
use num_traits::Zero;
use std::ops::*;

pub struct ECDSAAccount {
    entropy: Vec<u8>,
    mnemonic: String,

    JsonPrivateKey: String,
    JsonPublicKey: String,
    Address: String,
}

/*
pub fn generate_account_by_mnemonic(mnemonic: &String, lang: Language) -> Result<ECDSAAccount> {
    let cryptography = get_crypto_byte_from_mnemonic(mnemonic, lang)?;
    if cryptography != (super::address::CryptoType::NIST as u8) {
        return Err(Error::from(ErrorKind::ErrCryptographyNotSupported));
    }

    let password = "yes, you are handsome.".to_string();
    let seed = rand::generate_seed_with_error_check(mnemonic, &password, 40, lang)?;

    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING;
    let seed = untrusted::Input::from(&seed);
    let private_key = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, seed)?;

    // TO JSON
    // TODO
}
*/

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
