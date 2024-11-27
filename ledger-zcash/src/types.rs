use crate::config::{
    AK_SIZE, ALPHA_SIZE, HASHSEED_SIZE, IVK_SIZE, NF_SIZE, NSK_SIZE, OVK_SIZE, PK_LEN_SAPLING, PK_LEN_SECP256K1,
    RCV_SIZE, RSEED_SIZE, SIG_SIZE,
};

pub type PublicKeySecp256k1 = [u8; PK_LEN_SECP256K1];

pub type PaymentAddressRaw = [u8; PK_LEN_SAPLING];

pub type OutgoingViewKeyRaw = [u8; OVK_SIZE];

pub type RSeedRawAfterZip212 = [u8; RSEED_SIZE];

pub type NullifierRaw = [u8; NF_SIZE];

pub type SignatureRaw = [u8; SIG_SIZE];

/// -
pub type HashSeedRaw = [u8; HASHSEED_SIZE];

pub type AkSubgroupPointRaw = [u8; AK_SIZE];

pub type NskFrRaw = [u8; NSK_SIZE];

pub type RcvFrRaw = [u8; RCV_SIZE];

pub type AlphaFrRaw = [u8; ALPHA_SIZE];

pub type IvkFrRaw = [u8; IVK_SIZE];

pub type Secp256k1EcdsaCompactRaw = [u8; SIG_SIZE];
