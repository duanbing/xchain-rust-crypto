pub use crate::sign::ecdsa::EcdsaKeyPair;
pub use crate::sign::ecdsa::KeyPair;

use crate::errors::*;
use crate::ring::aead::BoundKey;
use bytes::{BufMut, BytesMut};
use rand::Rng;
use std::str::FromStr;

const INITIAL_SALT: [u8; 20] = [
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
    0xbe, 0xf9, 0xf5, 0x02,
];
#[allow(non_snake_case)]
pub fn encrypt<B: AsRef<[u8]>>(
    public_key: &crate::sign::ecdsa::UnparsedPublicKey<B>,
    s1: &[u8],
    s2: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>> {
    let public_key_ops = &super::ops::p256::PUBLIC_KEY_OPS;
    let private_key_ops = &super::ops::p256::PRIVATE_KEY_OPS;
    let common_ops = &super::ops::p256::COMMON_OPS;

    // generate random r
    let mut r = vec![0u8; 32];
    rand::thread_rng().fill(&mut r[..]);
    let sk = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(
        &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING,
        untrusted::Input::from(&r),
    )?;

    /*
    let test_d = "53768679905418652195332718418769459982443772351542749441444565000031408387094";
    let seed_bytes = num_bigint::BigInt::from_str(&test_d).unwrap().to_bytes_be();
    let seed = untrusted::Input::from(&seed_bytes.1);
    let sk = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(
        &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING,
        seed,
    )?;
    */

    //println!("k_B = {:?}", sk.seed_as_bytes());
    let R = sk.public_key();
    println!("R = {:?}", R.as_ref());
    // derive shared secret: S = P_x, where P = r * K_b
    let K_b = super::public_key::parse_uncompressed_point(
        &public_key_ops,
        untrusted::Input::from(public_key.as_ref()),
    )?;

    /*
    let seed = super::super::keys::Seed::from_bytes(
        &super::curve::P256,
        untrusted::Input::from(&sk.seed_as_bytes()),
    )?;
    let d = super::private_key::private_key_as_scalar(&private_key_ops, &seed);
    */
    let d = super::scalar_parse_big_endian_variable(
        common_ops,
        crate::limb::AllowZero::No,
        untrusted::Input::from(&sk.seed_as_bytes()),
    )?;
    println!(
        "before point_mul: d={:?}\nK_b.0={:?}\nK_b.1={:?}",
        d.limbs, K_b.0.limbs, K_b.1.limbs
    );
    let P = private_key_ops.point_mul(&d, &K_b);
    // TODO check P != 0

    let mut secret = vec![];
    let x_1 = common_ops.point_x(&P);
    let mut x_1_unencoded = common_ops.elem_unencoded(&x_1);
    println!("P_x = {:?}", x_1_unencoded.limbs);
    let x_1_len = x_1_unencoded.limbs.len() * 8;
    let x_1_slice =
        unsafe { std::slice::from_raw_parts(x_1_unencoded.limbs.as_mut_ptr() as *mut u8, x_1_len) };
    // k_e, k_m = KDF(S || S_1)
    secret.extend_from_slice(&x_1_slice);
    secret.extend_from_slice(s1);
    //println!("source secret: {:?}", &secret[..]);
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &INITIAL_SALT);
    let initial_secret = salt.extract(&secret);
    let mut secret = [0; 64];

    const LABEL: &[u8] = b""; //TODO
    hkdf_expand_label(&initial_secret, LABEL, &mut secret)?;

    //println!("secret: {:?}", &secret[..]);
    let (k_e, k_m) = secret.split_at(secret.len() / 2);
    //println!("k_e: {:?}", k_e);

    let c = aes_encrypt(k_e, msg)?;
    let d = message_tag(k_m, &c, s2)?;
    //println!("d = {:?}", d);

    //R || c || d
    let mut res = vec![];
    res.extend_from_slice(R.as_ref());
    res.extend_from_slice(&c);
    res.extend_from_slice(&d);
    Ok(res)
}

#[allow(non_snake_case)]
pub fn decrypt(sk: &EcdsaKeyPair, c: &[u8], s1: &[u8], s2: &[u8]) -> Result<Vec<u8>> {
    let public_key_ops = &super::ops::p256::PUBLIC_KEY_OPS;
    let private_key_ops = &super::ops::p256::PRIVATE_KEY_OPS;
    let common_ops = &super::ops::p256::COMMON_OPS;
    let R = &c[0..65];
    println!("R = {:?}", R.as_ref());
    let R =
        super::public_key::parse_uncompressed_point(&public_key_ops, untrusted::Input::from(R))?;
    // S = P_x, P = (P_x, P_y) = k_B * R
    /*
    let seed = super::super::keys::Seed::from_bytes(
        &super::curve::P256,
        untrusted::Input::from(&sk.seed_as_bytes()),
    )?;
    let k_B = super::private_key::private_key_as_scalar(&private_key_ops, &seed);
    println!(
        "before point_mul: d={:?}\nK_b.0={:?}\nK_b.1={:?}",
        k_B.limbs, R.0.limbs, R.1.limbs
    );
    */
    let k_B = super::scalar_parse_big_endian_variable(
        common_ops,
        crate::limb::AllowZero::No,
        untrusted::Input::from(&sk.seed_as_bytes()),
    )?;

    println!(
        "before point_mul: d={:?}\nK_b.0={:?}\nK_b.1={:?}",
        k_B.limbs, R.0.limbs, R.1.limbs
    );
    let P = private_key_ops.point_mul(&k_B, &R);
    let mut secret = vec![];
    let x_1 = common_ops.point_x(&P);
    let mut x_1_unencoded = common_ops.elem_unencoded(&x_1);
    println!("P_x = {:?}", x_1_unencoded.limbs);
    let x_1_len = x_1_unencoded.limbs.len() * 8;
    let x_1_slice =
        unsafe { std::slice::from_raw_parts(x_1_unencoded.limbs.as_mut_ptr() as *mut u8, x_1_len) };
    // S || S_1
    secret.extend_from_slice(&x_1_slice);
    secret.extend_from_slice(s1);

    //println!("source secret: {:?}", &secret[..]);
    // k_e, k_m = KDF(S || S_1)
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &INITIAL_SALT);
    let initial_secret = salt.extract(&secret);
    let mut secret = [0; 64];

    const LABEL: &[u8] = b""; //TODO
    hkdf_expand_label(&initial_secret, LABEL, &mut secret)?;

    //println!("secret: {:?}", &secret[..]);
    let (k_e, k_m) = secret.split_at(secret.len() / 2);
    //println!("k_e: {:?}", k_e);

    let cc = &c[65..(c.len() - 32)];
    let d = message_tag(k_m, cc, s2)?;
    let dd = &c[(c.len() - 32)..];
    // compare k_m and  d
    if d != dd {
        println!("MAC is invalid, {:?} != {:?}", d, k_m);
        return Err(Error::from(ErrorKind::CryptoError));
    }

    let m = aes_decrypt(k_e, cc)?;
    return Ok(m);
}

fn message_tag(k_m: &[u8], c: &[u8], s2: &[u8]) -> Result<Vec<u8>> {
    println!(
        "message_tag: k_m = {}. c = {}, s2 = {}",
        k_m.len(),
        c.len(),
        s2.len()
    );
    let mut msg = vec![];
    msg.extend_from_slice(c);
    msg.extend_from_slice(s2);
    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &k_m);
    let signature = ring::hmac::sign(&s_key, &msg);
    Ok(signature.as_ref().to_vec())
}

fn aes_encrypt(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let ubk = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
        .map_err(|_| Error::from(ErrorKind::CryptoError))?;
    let nonce = RingAeadNonceSequence::new();
    let mut sealing_key = ring::aead::SealingKey::new(ubk, nonce);
    let in_out_len = msg.len() + ring::aead::AES_256_GCM.tag_len();
    let mut in_out = BytesMut::with_capacity(in_out_len);
    in_out.put_slice(msg);
    let aad = ring::aead::Aad::empty();
    sealing_key
        .seal_in_place_append_tag(aad, &mut in_out)
        .map_err(|_| Error::from(ErrorKind::CryptoError))?;
    Ok((&in_out[..in_out_len]).to_vec())
}

fn aes_decrypt(key: &[u8], c: &[u8]) -> Result<Vec<u8>> {
    let ubk = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
        .map_err(|_| Error::from(ErrorKind::CryptoError))?;
    let nonce = RingAeadNonceSequence::new();
    let mut opening_key = ring::aead::OpeningKey::new(ubk, nonce);
    let mut in_out = BytesMut::with_capacity(c.len());
    in_out.put_slice(c);

    let aad = ring::aead::Aad::empty();
    let m = opening_key
        .open_in_place(aad, &mut in_out)
        .map_err(|_| Error::from(ErrorKind::CryptoError))?;
    Ok(m.to_vec())
}

fn hkdf_expand_label(prk: &ring::hkdf::Prk, label: &[u8], out: &mut [u8]) -> Result<()> {
    const LABEL_PREFIX: &[u8] = b"ecies xchain";

    let out_len = (out.len() as u16).to_be_bytes();
    let label_len = (LABEL_PREFIX.len() + label.len()) as u8;

    let info = [&out_len, &[label_len][..], LABEL_PREFIX, label, &[0][..]];

    prk.expand(&info, ArbitraryOutputLen(out.len()))
        .map_err(|_| Error::from(ErrorKind::CryptoError))?
        .fill(out)
        .map_err(|_| Error::from(ErrorKind::CryptoError))?;

    Ok(())
}

// The ring HKDF expand() API does not accept an arbitrary output length, so we
// need to hide the `usize` length as part of a type that implements the trait
// `ring::hkdf::KeyType` in order to trick ring into accepting it.
struct ArbitraryOutputLen(usize);

impl ring::hkdf::KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl RingAeadNonceSequence {
    fn new() -> RingAeadNonceSequence {
        RingAeadNonceSequence {
            nonce: [0u8; ring::aead::NONCE_LEN],
        }
    }
}

impl ring::aead::NonceSequence for RingAeadNonceSequence {
    fn advance(&mut self) -> std::result::Result<ring::aead::Nonce, ring::error::Unspecified> {
        let nonce = ring::aead::Nonce::assume_unique_for_key(self.nonce);
        increase_nonce(&mut self.nonce);
        Ok(nonce)
    }
}

pub fn increase_nonce(nonce: &mut [u8]) {
    for i in nonce {
        if std::u8::MAX == *i {
            *i = 0;
        } else {
            *i += 1;
            return;
        }
    }
}
pub struct RingAeadNonceSequence {
    nonce: [u8; ring::aead::NONCE_LEN],
}

#[cfg(test)]
mod tests {
    use super::*;
    pub use crate::sign::ecdsa::KeyPair;
    use rand::Rng;
    use std::str::FromStr;
    #[test]
    fn test_aes() {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill(&mut key[..]);

        let msg = "nihao, hello, world";
        let c = aes_encrypt(&key, msg.as_bytes());
        assert_eq!(c.is_ok(), true);
        let c = c.unwrap();

        let p = aes_decrypt(&key, &c);
        assert_eq!(p.is_ok(), true);
        let p = p.unwrap();
        assert_eq!(p, msg.as_bytes().to_vec());
    }

    #[test]
    fn test_ecies() {
        let d = "29079635126530934056640915735344231956621504557963207107451663058887647996601";
        let seed_bytes = num_bigint::BigInt::from_str(&d).unwrap().to_bytes_be();
        let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING;
        let seed = untrusted::Input::from(&seed_bytes.1);
        let private_key = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, seed);
        assert_eq!(private_key.is_ok(), true);
        let private_key = private_key.unwrap();
        let msg = "hello, son!";
        let s1 = vec![];
        let s2 = vec![];

        let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = crate::sign::ecdsa::UnparsedPublicKey::new(alg, private_key.public_key());

        let cipher = encrypt(&public_key, &s1, &s2, msg.as_bytes());
        assert_eq!(cipher.is_ok(), true);
        let cipher = cipher.unwrap();
        println!("cipher length : {}", cipher.len());
        let plain = decrypt(&private_key, &cipher, &s1, &s2);

        assert_eq!(plain.is_ok(), true);
        assert_eq!(msg.as_bytes().to_vec(), (plain.unwrap()));
    }
}
