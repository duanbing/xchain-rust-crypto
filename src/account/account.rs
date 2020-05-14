use super::address::{self, CryptoType};
use super::json_key;
use crate::errors::{Error, ErrorKind, Result};
use crate::hdwallet::{rand as wallet_rand, Language};
use crate::sign::ecdsa::EcdsaKeyPair;
use crate::sign::ecdsa::KeyPair;

use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

#[derive(Debug)]
pub struct ECDSAAccount {
    entropy: Vec<u8>,
    mnemonic: String,

    json_private_key: String,
    json_public_key: String,
    address: String,
}

// FIXME: fake safe
//  1. overflow check
fn get_safe_seed(seed: &[u8]) -> Result<untrusted::Input> {
    Ok(untrusted::Input::from(&seed))
}

pub fn generate_account_by_mnemonic(mnemonic: &String, lang: Language) -> Result<ECDSAAccount> {
    get_crypto_byte_from_mnemonic(mnemonic, lang)?;
    let password = "yes, you are handsome.".to_string();

    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING;
    //TODO should not hard code the bitsize
    let seed_raw = wallet_rand::generate_seed_with_error_check(mnemonic, &password, 32, lang)?;
    println!("seed.len = {}", seed_raw.len());
    let seed = get_safe_seed(&seed_raw)?;
    let private_key = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, seed)?;

    // TO JSON
    // TODO 这里不符合规范，最好是pcks8格式
    let json_sk = json_key::get_ecdsa_private_key_json_format(&private_key)?;
    let json_pk = json_key::get_ecdsa_public_key_json_format(&private_key)?;

    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
    let public_key = crate::sign::ecdsa::UnparsedPublicKey::new(alg, private_key.public_key());
    let address = address::get_address_from_public_key(&public_key)?;

    Ok(ECDSAAccount {
        entropy: seed_raw,
        mnemonic: mnemonic.to_string(),
        json_public_key: json_pk,
        json_private_key: json_sk,
        address: address,
    })
}

fn to_tag_byte(cryptography: u8) -> u8 {
    (cryptography & 15) << 4
}

fn from_tag_byte(tag_byte: u8) -> u8 {
    (tag_byte >> 4) & 15
}

pub fn get_crypto_byte_from_mnemonic(mnemonic: &String, lang: Language) -> Result<CryptoType> {
    println!("get_crypto_byte_from_mnemonic");
    let entropy = wallet_rand::get_entropy_from_mnemonic(mnemonic, lang)?;
    let tag_byte = entropy[entropy.len() - 1]; // 8bits
    println!("tag_byte {:?}", tag_byte);
    let cryptography_int = from_tag_byte(tag_byte);
    println!("{:?}", cryptography_int);
    CryptoType::from_u8(cryptography_int)
}

pub fn create_new_account_with_mnemonic(
    lang: Language,
    strength: wallet_rand::KeyStrength,
    crypto: CryptoType,
) -> Result<ECDSAAccount> {
    let strength = wallet_rand::get_bits_len(strength);
    let mut entropybytes = wallet_rand::generate_entropy(strength)?;
    let tag_byte = to_tag_byte(CryptoType::to_u8(crypto));

    println!("begin generate_mnemonic, tag = {}", tag_byte);
    entropybytes.push(tag_byte);
    let mnemonic = wallet_rand::generate_mnemonic(&entropybytes, lang)?;
    println!("generate_account_by_mnemonic");
    generate_account_by_mnemonic(&mnemonic, lang)
}

pub fn export_new_account_with_mnenomic(
    base_path: &str,
    lang: Language,
    strength: wallet_rand::KeyStrength,
    cryptography: CryptoType,
) -> Result<()> {
    let acc = create_new_account_with_mnemonic(lang, strength, cryptography)?;
    let path: PathBuf = [base_path, "mnenomic"].iter().collect();
    let mut file = File::create(path)?;
    file.write_all(acc.mnemonic.as_bytes())?;

    let path: PathBuf = [base_path, "private.key"].iter().collect();
    let mut file = File::create(path)?;
    file.write_all(acc.json_private_key.as_bytes())?;

    let path: PathBuf = [base_path, "public.key"].iter().collect();
    let mut file = File::create(path)?;
    file.write_all(acc.json_public_key.as_bytes())?;

    let path: PathBuf = [base_path, "address"].iter().collect();
    let mut file = File::create(path)?;
    file.write_all(acc.address.as_bytes())?;
    Ok(())
}

pub fn export_new_account(base_path: &str, private_key: &EcdsaKeyPair) -> Result<()> {
    let json_sk = json_key::get_ecdsa_private_key_json_format(private_key)?;
    let json_pk = json_key::get_ecdsa_public_key_json_format(private_key)?;
    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
    let public_key = crate::sign::ecdsa::UnparsedPublicKey::new(alg, private_key.public_key());
    let address = address::get_address_from_public_key(&public_key)?;
    let path: PathBuf = [base_path, "private.key"].iter().collect();
    let mut file = File::create(path)?;
    file.write_all(json_sk.as_bytes())?;

    let path: PathBuf = [base_path, "public.key"].iter().collect();
    let mut file = File::create(path)?;
    file.write_all(json_pk.as_bytes())?;

    let path: PathBuf = [base_path, "address"].iter().collect();
    let mut file = File::create(path)?;
    file.write_all(address.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_create_account() {
        let res = create_new_account_with_mnemonic(
            Language::ChineseSimplified,
            wallet_rand::KeyStrength::HARD,
            CryptoType::NIST,
        );
        assert_eq!(res.is_ok(), true);
    }

    #[test]
    fn test_open_account() {}

    #[test]
    fn test_save_account() {}

}
