use crate::sign::ecdsa::EcdsaKeyPair;
use crate::sign::ecdsa::KeyPair;
use num_bigint::BigInt;
use num_bigint::Sign::Plus;

use serde::{ser::Serializer, Deserialize, Serialize};

use super::PublicKey;
use crate::errors::*;

///unsafe. 这里全是是为了按照超级链目前方式进行秘钥格式化
fn big_serialize<S>(x: &BigInt, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(x.to_str_radix(10).as_str())
}
#[derive(Serialize, Deserialize, Debug)]
struct ECDSAPrivateKey {
    #[serde(rename = "Curvename")]
    curve_name: String,
    #[serde(rename = "X", serialize_with = "big_serialize")]
    x: BigInt,
    #[serde(rename = "Y", serialize_with = "big_serialize")]
    y: BigInt,
    #[serde(rename = "D", serialize_with = "big_serialize")]
    d: BigInt,
}

impl ECDSAPrivateKey {
    fn from(sk: &EcdsaKeyPair) -> Self {
        let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let public_key = crate::sign::ecdsa::UnparsedPublicKey::new(alg, sk.public_key());
        let xy = public_key.xy();
        let x = BigInt::from_bytes_be(Plus, xy.0);
        let y = BigInt::from_bytes_be(Plus, xy.1);

        let seed = sk.seed_as_bytes();

        Self {
            curve_name: String::from("P-256"),
            x: x,
            y: y,
            d: BigInt::from_bytes_be(Plus, &seed),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ECDSAPublicKey {
    #[serde(rename = "Curvename")]
    curve_name: String,
    #[serde(rename = "X", serialize_with = "big_serialize")]
    x: BigInt,
    #[serde(rename = "Y", serialize_with = "big_serialize")]
    y: BigInt,
}

impl ECDSAPublicKey {
    fn from<B: AsRef<[u8]>>(pk: &PublicKey<B>) -> Self {
        let xy = pk.xy();
        let x = BigInt::from_bytes_be(Plus, xy.0);
        let y = BigInt::from_bytes_be(Plus, xy.1);
        Self {
            curve_name: String::from("P-256"),
            x: x,
            y: y,
        }
    }
}

/// 将私钥转换成为json
///  格式例子： {"Curvname":"P-256","X":74695617477160058757747208220371236837474210247114418775262229497812962582435,"Y":51348715319124770392993866417088542497927816017012182211244120852620959209571,"D":29079635126530934056640915735344231956621504557963207107451663058887647996601}
///
pub fn get_ecdsa_private_key_json_format<'a>(k: &EcdsaKeyPair) -> Result<String> {
    let r = serde_json::to_string(&ECDSAPrivateKey::from(k))?;
    Ok(r)
}

pub fn get_ecdsa_public_key_json_format<'a>(k: &EcdsaKeyPair) -> Result<String> {
    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
    let public_key = crate::sign::ecdsa::UnparsedPublicKey::new(alg, k.public_key());
    let r = serde_json::to_string(&ECDSAPublicKey::from(&public_key))?;
    Ok(r)
}

pub fn get_ecdsa_public_key_json_format_from_public_key<'a, B: AsRef<[u8]>>(
    pk: &PublicKey<B>,
) -> Result<String> {
    let r = serde_json::to_string(&ECDSAPublicKey::from(pk))?;
    Ok(r)
}

#[test]
fn dump_all_test() {
    let key_slice = hex::decode(
        "04a664e9bbf6d03e4b75758f7ee3732a0a8eff9e76a0edc9a14ca584b966493664d0d8b7871c5b33bdee9f0e154d7eb948356229e7694cb04a785520952dae1438",
    )
    .unwrap();

    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
    let public_key = crate::sign::ecdsa::UnparsedPublicKey::new(alg, &key_slice);
    let msg = String::from("hello world");
    let sig = hex::decode("3046022100873aad44cea8badf28c8f6b4509763e875a21805daf971bffc3a9bd27288a30b022100899216a47e3f071ede3d697bb172b94a9240d0c8cc6a5754a68edc00e1752873").unwrap();
    let res = public_key.verify(&msg.as_bytes(), &sig);
    println!("{:?}", res);

    let res = get_ecdsa_public_key_json_format_from_public_key(&public_key).unwrap();
    println!("json: {:?}", res);
}

#[test]
pub fn test_seed_private_public() {
    use std::str::FromStr;
    let d = "29079635126530934056640915735344231956621504557963207107451663058887647996601";
    let seed_bytes = num_bigint::BigInt::from_str(&d).unwrap().to_bytes_be();
    let alg = &crate::sign::ecdsa::ECDSA_P256_SHA256_ASN1_SIGNING;
    let seed = untrusted::Input::from(&seed_bytes.1);
    let private_key = crate::sign::ecdsa::EcdsaKeyPair::from_seed_unchecked(alg, seed);
    assert_eq!(private_key.is_ok(), true);
    let private_key = private_key.unwrap();
    let res = get_ecdsa_private_key_json_format(&private_key);
    println!("json: {:?}", res);
}
