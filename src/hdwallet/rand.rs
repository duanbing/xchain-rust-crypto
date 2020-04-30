use super::languages::*;
use crate::errors::{Error, ErrorKind, Result};
use rand::prelude::*;

use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use std::ops::*;

lazy_static! {
    static ref RIGHT_SHIFT_11BITS_DIVIDER: num_bigint::BigInt =
        { num_bigint::BigInt::from_i32(2048).unwrap() };
    static ref BIGINT_ZERO: num_bigint::BigInt = { num_traits::Zero::zero() };
    static ref BIGINT_ONE: num_bigint::BigInt = { num_traits::One::one() };
}

//  检查试图获取的Entropy的比特大小是否符合规范要求：
//  在128-256之间，并且是32的倍数
//  为什么这么设计，详见比特币改进计划第39号提案的数学模型
//
//  checksum length (CS)
//  entropy length (ENT)
//  mnemonic sentence (MS)
//
//	CS = ENT / 32
//	MS = (ENT + CS) / 11
//
//	|  ENT  | CS | ENT+CS |  MS  |
//	+-------+----+--------+------+
//	|  128  |  4 |   132  |  12  |
//	|  160  |  5 |   165  |  15  |
//	|  192  |  6 |   198  |  18  |
//	|  224  |  7 |   231  |  21  |
//	|  256  |  8 |   264  |  24  |
fn validate_entropy_bit_size(bit_size: usize) -> Result<()> {
    if (bit_size) % 32 != 0 || (bit_size + 8) < 128 || (bit_size + 8) > 256 {
        return Err(Error::from(ErrorKind::ErrInvalidEntropyLength));
    }
    Ok(())
}

pub fn generate_entropy(bit_size: usize) -> Result<Vec<u8>> {
    validate_raw_entropy_bit_size(bit_size)?;
    let mut ent = vec![0u8; bit_size / 8];
    rand::thread_rng().fill_bytes(&mut ent);
    Ok(ent)
}

fn validate_raw_entropy_bit_size(bit_size: usize) -> Result<()> {
    if (bit_size + 8) % 32 != 0 || (bit_size + 8) < 128 || (bit_size + 8) > 256 {
        return Err(Error::from(ErrorKind::ErrInvalidEntropyLength));
    }
    Ok(())
}

pub fn generate_mnemonic(entropy: &[u8], l: Language) -> Result<String> {
    let entropy_bit_len = entropy.len() << 3;
    validate_entropy_bit_size(entropy_bit_len)?;

    let word_list = get_word_list_by_langs(l);
    let checksum_bit_len = entropy_bit_len >> 5;
    let mut entropy_int = add_checksum(entropy);

    let sentense_len = (entropy_bit_len + checksum_bit_len) / 11;
    let mut words = vec![String::from(""); sentense_len];
    let mut word = BIGINT_ZERO.clone();
    for i in (sentense_len..0).rev() {
        word.bitand_assign(entropy_int.clone());
        entropy_int.div_assign(RIGHT_SHIFT_11BITS_DIVIDER.clone());
        let word_bytes = bytes_pad(word.to_bytes_be().1, 2);
        words[i] =
            word_list[&(num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &word_bytes)
                .to_i16()
                .unwrap() as u32)]
                .clone();
    }
    Ok(words.join(" "))
}

pub fn generate_old_entropy(entropy: &[u8], lang: Language) -> Result<String> {
    let entropy_bit_len = entropy.len() << 3;
    validate_entropy_bit_size(entropy_bit_len)?;
    let word_list = get_word_list_by_langs(lang);
    let checksum_bit_len = entropy_bit_len >> 5;
    let mut entropy_int = add_old_checksum(entropy);

    let sentense_len = (entropy_bit_len + checksum_bit_len) / 11;
    let mut words = vec![String::from(""); sentense_len];
    let mut word = BIGINT_ZERO.clone();
    for i in (sentense_len..0).rev() {
        word.bitand_assign(entropy_int.clone());
        entropy_int.div_assign(RIGHT_SHIFT_11BITS_DIVIDER.clone());
        let word_bytes = bytes_pad(word.to_bytes_be().1, 2);
        words[i] =
            word_list[&(num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &word_bytes)
                .to_i16()
                .unwrap() as u32)]
                .clone();
    }
    Ok(words.join(" "))
}

fn add_checksum(entropy: &[u8]) -> num_bigint::BigInt {
    let hb = crate::hash::hash::double_sha256(entropy);
    let _1st_checksum_byte = hb[1];
    let checksum_bit_len = entropy.len() >> 2;
    let mut data_bigint = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, entropy);
    let big_two = num_bigint::BigInt::from_i32(2).unwrap();
    let big_one = BIGINT_ONE.clone();
    for i in 0..checksum_bit_len {
        data_bigint.mul_assign(big_two.clone());
        if _1st_checksum_byte & (1 << (7 - i)) > 0 {
            data_bigint.bitxor_assign(big_one.clone());
        }
    }
    data_bigint
}

fn add_old_checksum(entropy: &[u8]) -> num_bigint::BigInt {
    let hb = crate::hash::hash::double_sha256(entropy);
    let _1st_checksum_byte = hb[0];
    let checksum_bit_len = entropy.len() >> 2;
    let mut data_bigint = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, entropy);
    let big_two = num_bigint::BigInt::from_i32(2).unwrap();
    let big_one = BIGINT_ONE.clone();
    for i in 0..checksum_bit_len {
        data_bigint.mul_assign(big_two.clone());
        if _1st_checksum_byte & (1 << (7 - i)) > 0 {
            data_bigint.bitxor_assign(big_one.clone());
        }
    }
    data_bigint
}

pub fn bytes_pad(v: Vec<u8>, sz: usize) -> Vec<u8> {
    if v.len() >= sz {
        return v;
    }
    let mut vret = vec![0u8; sz - v.len()];
    vret.append(&mut v.clone());
    vret
}

pub fn get_entropy_from_mnemonic(mnemonic: &String, lang: Language) -> Result<Vec<u8>> {
    let mnemonic_slice = get_words_from_valid_mnemonic_sentense(mnemonic, lang)?;
    let mnemonic_bit_size = mnemonic_slice.len() * 11;
    let checksum_bit_size = mnemonic_bit_size % 32;

    let mut b = BIGINT_ZERO.clone();
    let reversed_word_map = get_reversed_word_list_by_langs(lang);
    for w in mnemonic_slice {
        let idx: u16 = (*reversed_word_map.get(&w.to_string()).unwrap()) as u16;
        b.mul_assign(RIGHT_SHIFT_11BITS_DIVIDER.clone());
        b.bitxor_assign(num_bigint::BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &idx.to_be_bytes(),
        ));
    }
    let big_two = num_bigint::BigInt::from_i32(2).unwrap();
    let checksum_modulo = big_two.modpow(
        &num_bigint::BigInt::from_u32(checksum_bit_size as u32).unwrap(),
        &(RIGHT_SHIFT_11BITS_DIVIDER.clone()),
    );

    let mut entropy = b.clone();
    entropy.div_assign(checksum_modulo);
    let entropy_bytes_size = (mnemonic_bit_size - checksum_bit_size) / 8;
    let full_bytes_size = entropy_bytes_size + 1;
    let entropy_bytes = bytes_pad(entropy.to_bytes_be().1, entropy_bytes_size);
    let entropy_with_checksum_bytes = bytes_pad(b.to_bytes_be().1, full_bytes_size);

    let add1 = add_checksum(&entropy_bytes);
    let new_entropy_with_checksum_bytes = bytes_pad(add1.to_bytes_be().1, full_bytes_size);
    if new_entropy_with_checksum_bytes != entropy_with_checksum_bytes {
        return Err(Error::from(ErrorKind::ErrMnemonicChecksumIncorrect));
    }

    Ok(entropy.to_bytes_be().1)
}

pub fn get_old_entropy_from_mnemonic(mnemonic: &String, lang: Language) -> Result<Vec<u8>> {
    let mnemonic_slice = get_words_from_valid_mnemonic_sentense(mnemonic, lang)?;
    let mnemonic_bit_size = mnemonic_slice.len() * 11;
    let checksum_bit_size = mnemonic_bit_size % 32;

    let mut b = BIGINT_ZERO.clone();
    let reversed_word_map = get_reversed_word_list_by_langs(lang);
    for w in mnemonic_slice {
        let idx: u16 = (*reversed_word_map.get(&w.to_string()).unwrap()) as u16;
        b.mul_assign(RIGHT_SHIFT_11BITS_DIVIDER.clone());
        b.bitxor_assign(num_bigint::BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &idx.to_be_bytes(),
        ));
    }
    let big_two = num_bigint::BigInt::from_i32(2).unwrap();
    let checksum_modulo = big_two.modpow(
        &num_bigint::BigInt::from_u32(checksum_bit_size as u32).unwrap(),
        &(RIGHT_SHIFT_11BITS_DIVIDER.clone()),
    );

    let mut entropy = b.clone();
    entropy.div_assign(checksum_modulo);
    let entropy_bytes_size = (mnemonic_bit_size - checksum_bit_size) / 8;
    let full_bytes_size = entropy_bytes_size + 1;
    let entropy_bytes = bytes_pad(entropy.to_bytes_be().1, entropy_bytes_size);
    let entropy_with_checksum_bytes = bytes_pad(b.to_bytes_be().1, full_bytes_size);

    let add1 = add_old_checksum(&entropy_bytes);
    let new_entropy_with_checksum_bytes = bytes_pad(add1.to_bytes_be().1, full_bytes_size);
    if new_entropy_with_checksum_bytes != entropy_with_checksum_bytes {
        return Err(Error::from(ErrorKind::ErrMnemonicChecksumIncorrect));
    }

    Ok(entropy.to_bytes_be().1)
}

pub fn generate_seed_with_error_check(
    mnemonic: &String,
    password: &String,
    keylen: usize,
    lang: Language,
) -> Result<Vec<u8>> {
    get_entropy_from_mnemonic(mnemonic, lang)?;
    generate_seed(mnemonic, password, keylen)
}

// TODO:  password: mnimonic,
fn generate_seed(mnimonic: &String, password: &String, keylen: usize) -> Result<Vec<u8>> {
    let mut salt = "mnemonic".to_owned();
    salt.push_str(password);
    let mut to_store = vec![0u8; keylen];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        std::num::NonZeroU32::new(2048).unwrap(),
        salt.as_bytes(),
        mnimonic.as_bytes(),
        &mut to_store,
    );
    Ok(to_store.to_vec())
}

pub fn get_words_from_valid_mnemonic_sentense(
    mnemonic: &String,
    lang: Language,
) -> Result<Vec<&str>> {
    let words = get_words_from_mnemonic_sentense(mnemonic)?;
    let word_list = get_reversed_word_list_by_langs(lang);

    check_words_within_language_wordlist(&words, word_list)?;
    Ok(words)
}

pub fn get_words_from_mnemonic_sentense(mnemonic: &String) -> Result<Vec<&str>> {
    let word_list: Vec<&str> = mnemonic.split(' ').collect();
    match word_list.len() {
        12 | 15 | 18 | 21 | 24 => Ok(word_list),
        _ => Err(Error::from(ErrorKind::ErrMnemonicNumNotValid)),
    }
}

fn check_words_within_language_wordlist(
    words: &Vec<&str>,
    word_list: &std::collections::HashMap<String, u32>,
) -> Result<()> {
    for w in words {
        if let None = word_list.get(&w.to_string()) {
            return Err(Error::from(ErrorKind::ErrMnemonicNumNotValid));
        }
    }
    Ok(())
}

pub enum KeyStrength {
    EASY,
    MIDDLE,
    HARD,
}

pub fn get_bits_len(ks: KeyStrength) -> usize {
    match ks {
        KeyStrength::EASY => 128,
        KeyStrength::MIDDLE => 192,
        KeyStrength::HARD => 256,
    }
}

pub fn generate_seed_with_strength_and_keylen(
    strength: KeyStrength,
    keylen: usize,
) -> Result<Vec<u8>> {
    let entropy_bit_len = get_bits_len(strength);
    let entropy_byte = generate_entropy(entropy_bit_len)?;
    generate_seed_with_random_password(&entropy_byte, keylen)
}

fn generate_seed_with_random_password(password: &[u8], keylen: usize) -> Result<Vec<u8>> {
    let salt = "yes, you are handsome.";
    let mut to_store = vec![0u8; keylen];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        std::num::NonZeroU32::new(2048).unwrap(),
        salt.as_bytes(),
        password,
        &mut to_store,
    );
    Ok(to_store.to_vec())
}
