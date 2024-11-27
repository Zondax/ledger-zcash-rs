use std::str::*;

use group::GroupEncoding;
use jubjub::{Fr, SubgroupPoint};
use serde::{de::Error, Deserialize, Deserializer, Serializer};
use zcash_primitives::{
    keys::OutgoingViewingKey,
    legacy::Script,
    memo::MemoBytes as Memo,
    merkle_tree::{IncrementalWitness, MerklePath},
    sapling::{redjubjub::Signature, Node, PaymentAddress, ProofGenerationKey, Rseed},
    transaction::components::{Amount, OutPoint},
};

use crate::HashSeed;

/**
 * Deserializes a transaction outpoint from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `OutPoint` or an error.
 */
pub fn t_outpoint_deserialize<'de, D>(deserializer: D) -> Result<OutPoint, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 36];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
    OutPoint::read(&bytes[..]).map_err(D::Error::custom)
}

/**
 * Deserializes a public key from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `secp256k1::PublicKey` or an error.
 */
pub fn t_pk_deserialize<'de, D>(deserializer: D) -> Result<secp256k1::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    secp256k1::PublicKey::from_str(&str).map_err(D::Error::custom)
}

/**
 * Deserializes a script from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `Script` or an error.
 */
pub fn script_deserialize<'de, D>(deserializer: D) -> Result<Script, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 26];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
    Script::read(&bytes[..]).map_err(D::Error::custom)
}

/**
 * Deserializes an amount from a u64 value.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `Amount` or an error.
 */
pub fn amount_deserialize<'de, D>(deserializer: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let v = u64::deserialize(deserializer)?;
    let r = Amount::from_u64(v);
    match r {
        Ok(a) => Ok(a),
        Err(_) => Err(D::Error::custom("error deserializing hex to amount")),
    }
}

/**
 * Deserializes a field element `Fr` from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `Fr` or an error.
 */
pub fn fr_deserialize<'de, D>(deserializer: D) -> Result<Fr, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
    let f = Fr::from_bytes(&bytes);
    if f.is_some().into() {
        Ok(f.unwrap())
    } else {
        Err(D::Error::custom("error deserializing to fr"))
    }
}

/**
 * Deserializes a `ProofGenerationKey` from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `ProofGenerationKey` or an error.
 */
pub fn pgk_deserialize<'de, D>(deserializer: D) -> Result<ProofGenerationKey, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 64];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;

    let mut akb = [0u8; 32];
    akb.copy_from_slice(&bytes[0 .. 32]);
    let mut nskb = [0u8; 32];
    nskb.copy_from_slice(&bytes[32 .. 64]);

    let ak = SubgroupPoint::from_bytes(&akb);
    let nsk = jubjub::Fr::from_bytes(&nskb);
    if ak.is_some().into() && nsk.is_some().into() {
        Ok(ProofGenerationKey { ak: ak.unwrap(), nsk: nsk.unwrap() })
    } else {
        Err(D::Error::custom("error deserializing to pgk"))
    }
}

/**
 * Deserializes a `PaymentAddress` from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `PaymentAddress` or an error.
 */
pub fn s_address_deserialize<'de, D>(deserializer: D) -> Result<PaymentAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 43];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;

    let p = PaymentAddress::from_bytes(&bytes);
    if let Some(addr) = p {
        Ok(addr)
    } else {
        Err(D::Error::custom("error deserializing to shielded address"))
    }
}

/**
 * Deserializes an `OutgoingViewingKey` from an optional hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `Option<OutgoingViewingKey>` or an error.
 */
pub fn ovk_deserialize<'de, D>(deserializer: D) -> Result<Option<OutgoingViewingKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let str: Option<String> = Option::deserialize(deserializer)?;
    if let Some(s) = str {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s, &mut bytes).map_err(D::Error::custom)?;
        Ok(Some(OutgoingViewingKey(bytes)))
    } else {
        Ok(None)
    }
}

/**
 * Deserializes a `Memo` from a hex-encoded string, handling empty or invalid formats.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `Option<Memo>` or an error.
 */
pub fn memo_deserialize<'de, D>(deserializer: D) -> Result<Option<Memo>, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;

    if str.len() == 4 || str.len() % 2 != 0 {
        Ok(None)
    } else {
        let mut bytes = Vec::with_capacity(str.len() / 2);
        hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
        if bytes.is_empty() {
            Ok(Some(Memo::empty()))
        } else {
            Ok(Memo::from_bytes(&bytes[..]).ok())
        }
    }
}

/**
 * Deserializes a `MerklePath` for a `Node` from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `MerklePath<Node>` or an error.
 */
pub fn merkle_path_deserialize<'de, D>(deserializer: D) -> Result<MerklePath<Node>, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let v = hex::decode(str).map_err(D::Error::custom)?;
    let path = IncrementalWitness::read(&v[..])
        .map_err(D::Error::custom)?
        .path()
        .ok_or_else(|| D::Error::custom("tree was empty"))?;

    Ok(path)
}

/**
 * Deserializes a `Rseed` from a hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `Rseed` or an error.
 */
pub fn rseed_deserialize<'de, D>(deserializer: D) -> Result<Rseed, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(str, &mut bytes).map_err(D::Error::custom)?;
    let rseed = Rseed::AfterZip212(bytes);
    Ok(rseed)
}

/**
 * Deserializes a list of `secp256k1::ecdsa::Signature` from a list of hex-encoded strings.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized list of `secp256k1::ecdsa::Signature` or an error.
 */
pub fn t_sig_deserialize<'de, D>(deserializer: D) -> Result<Vec<secp256k1::ecdsa::Signature>, D::Error>
where
    D: Deserializer<'de>,
{
    let str: Vec<String> = Deserialize::deserialize(deserializer)?;
    if str.is_empty() {
        Ok(Vec::new())
    } else {
        let n = str.len();
        let mut v = Vec::new();
        for item in str.iter() {
            if item.len() != 128 {
                return Err(D::Error::custom("not enough bytes deserializing to transparent sig"));
            }
            let mut bytes = [0u8; 64];
            hex::decode_to_slice(item, &mut bytes).map_err(D::Error::custom)?;
            let s = secp256k1::ecdsa::Signature::from_compact(&bytes).map_err(D::Error::custom)?;
            v.push(s);
        }
        Ok(v)
    }
}

/**
 * Deserializes a list of `Signature` from a list of hex-encoded strings.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized list of `Signature` or an error.
 */
pub fn s_sig_deserialize<'de, D>(deserializer: D) -> Result<Vec<Signature>, D::Error>
where
    D: Deserializer<'de>,
{
    let str: Vec<String> = Deserialize::deserialize(deserializer)?;
    if str.is_empty() {
        Ok(Vec::new())
    } else {
        let n = str.len();
        let mut v = Vec::new();
        for item in str.iter().take(n) {
            if item.len() != 128 {
                return Err(D::Error::custom("not enough bytes deserializing to transparent sig"));
            }
            let mut bytes = [0u8; 64];
            hex::decode_to_slice(item, &mut bytes).map_err(D::Error::custom)?;
            let s = Signature::read(&bytes[..]);
            if s.is_err() {
                return Err(D::Error::custom("error deserializing to spend sig"));
            }
            v.push(s.unwrap());
        }
        Ok(v)
    }
}

/**
 * Deserializes an optional `HashSeed` from an optional hex-encoded string.
 *
 * @param deserializer - The deserializer instance.
 * @returns A result containing the deserialized `Option<HashSeed>` or an error.
 */
pub fn hashseed_deserialize<'de, D>(deserializer: D) -> Result<Option<HashSeed>, D::Error>
where
    D: Deserializer<'de>,
{
    let str: Option<String> = Option::deserialize(deserializer)?;
    if let Some(s) = str {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s, &mut bytes).map_err(D::Error::custom)?;
        Ok(Some(HashSeed(bytes)))
    } else {
        Ok(None)
    }
}
