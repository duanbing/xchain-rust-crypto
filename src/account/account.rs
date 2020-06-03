use super::address::{self, CryptoType};
use super::json_key;
use crate::errors::{Error, ErrorKind, Result};
use crate::hdwallet::{rand as wallet_rand, Language};
use crate::sign::ecdsa::EcdsaKeyPair;
use crate::sign::ecdsa::KeyPair;

use num_integer::Integer;
use num_traits::Num;
use std::ops::{AddAssign, SubAssign};

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

/// From: https://golang.org/src/crypto/elliptic/p256.go
const P256_N: &str =
    "115792089210356248762697446949407573529996955224135760342422259061068512044369";

/// safe check
///  1. overflow check, range is [0, n)
fn get_safe_seed(seed: &[u8]) -> Result<Vec<u8>> {
    let big_one: num_bigint::BigInt = num_traits::One::one();
    let big_n = num_bigint::BigInt::from_str_radix(P256_N, 10)
        .map_err(|_| Error::from(ErrorKind::ParseError))?;
    let mut big_n_sub_1 = big_n.clone();
    // N - 1
    big_n_sub_1.sub_assign(&big_one);

    let big_seed = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, seed);
    // mod =  big_seed^1 % (N - 1)
    let mut big_seed = big_seed.mod_floor(&big_n_sub_1);

    // mod + 1 -> [0, N)
    big_seed.add_assign(&big_one);

    Ok(big_seed.to_bytes_be().1)
}

pub fn generate_account_by_mnemonic(mnemonic: &String, lang: Language) -> Result<ECDSAAccount> {
    get_crypto_byte_from_mnemonic(mnemonic, lang)?;
    let password = "jingbo is handsome!".to_string();

    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING;
    //TODO should not hard code the bitsize
    let seed_raw = wallet_rand::generate_seed_with_error_check(mnemonic, &password, 40, lang)?;
    let seed = get_safe_seed(&seed_raw)?;
    let private_key =
        crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, untrusted::Input::from(&seed))?;

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
    let entropy = wallet_rand::get_entropy_from_mnemonic(mnemonic, lang)?;
    let tag_byte = entropy[entropy.len() - 1]; // 8bits
    let cryptography_int = from_tag_byte(tag_byte);
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

    entropybytes.push(tag_byte);
    let mnemonic = wallet_rand::generate_mnemonic(&entropybytes, lang)?;
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
    fn test_check_account() {
        let mnemonic =
            String::from("呈 仓 冯 滚 刚 伙 此 丈 锅 语 揭 弃 精 塘 界 戴 玩 爬 奶 滩 哀 极 样 费");
        let acc = generate_account_by_mnemonic(&mnemonic, Language::ChineseSimplified);
        assert_eq!(acc.is_ok(), true);
        let acc = acc.unwrap();
        assert_eq!("nYA6bVyhzv38g85ejxr4aqeKPcbG8mSWC", &acc.address);
    }

    #[test]
    fn test_open_and_save_account() {
        let res = export_new_account_with_mnenomic(
            "/tmp/",
            Language::ChineseSimplified,
            wallet_rand::KeyStrength::HARD,
            CryptoType::NIST,
        );
        assert_eq!(res.is_ok(), true);

        //open get_ecdsa_private_key_from_file
        let res = super::json_key::get_ecdsa_private_key_from_file("/tmp/private.key");
        assert_eq!(res.is_ok(), true);
        let sk = res.unwrap();

        let res = export_new_account("/tmp", &sk);
        assert_eq!(res.is_ok(), true);
    }
}
