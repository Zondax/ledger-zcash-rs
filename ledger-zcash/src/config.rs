/// Application Identifier for Zcash commands
pub const CLA: u8 = 0x85;

/// Instruction to get Incoming Viewing Key
pub const INS_GET_IVK: u8 = 0xf0;
/// Instruction to get Outgoing Viewing Key
pub const INS_GET_OVK: u8 = 0xf1;
/// Instruction to get Nullifier
pub const INS_GET_NF: u8 = 0xf2;
/// Instruction to initialize a transaction
pub const INS_INIT_TX: u8 = 0xa0;
/// Instruction to extract spend data
pub const INS_EXTRACT_SPEND: u8 = 0xa1;
/// Instruction to extract output data
pub const INS_EXTRACT_OUTPUT: u8 = 0xa2;
/// Instruction to check and sign a transaction
pub const INS_CHECKANDSIGN: u8 = 0xa3;
/// Instruction to extract a spend signature
pub const INS_EXTRACT_SPENDSIG: u8 = 0xa4;
/// Instruction to extract a transaction signature
pub const INS_EXTRACT_TRANSSIG: u8 = 0xa5;
/// Instruction to get a list of diversifiers
pub const INS_GET_DIV_LIST: u8 = 0x09;

/// Instruction to get a secp256k1 address
pub const INS_GET_ADDR_SECP256K1: u8 = 0x01;
/// Instruction to get a Sapling address
pub const INS_GET_ADDR_SAPLING: u8 = 0x11;
/// Instruction to get a Sapling address with diversifier
pub const INS_GET_ADDR_SAPLING_DIV: u8 = 0x10;

////////////////////
////////////////////
////////////////////

/// Length of diversifier index
pub const DIV_INDEX_SIZE: usize = 11;
/// Diversifier length
pub const DIV_SIZE: usize = 11;
/// Number of diversifiers returned by get div list
pub const DIV_LIST_SIZE: usize = 220;

/// Outgoing Viewing Key size
pub const OVK_SIZE: usize = 32;

/// Incoming Viewing Key size
pub const IVK_SIZE: usize = 32;

/// Nullifier size
pub const NF_SIZE: usize = 32;

/// Note commitment size
pub const NOTE_COMMITMENT_SIZE: usize = 32;

/// SHA-256 digest size
pub const SHA256_DIGEST_SIZE: usize = 32;

/// Authorizing Key size
pub const AK_SIZE: usize = 32;

/// Nullifier Key size
pub const NSK_SIZE: usize = 32;

/// Alpha size (random scalar for Jubjub)
pub const ALPHA_SIZE: usize = 32;

/// RCV size (random scalar for value commitment)
pub const RCV_SIZE: usize = 32;

/// Spend data length: AK (32) + NSK (32) + Alpha(32) + RCV (32)
pub const SPENDDATA_SIZE: usize = AK_SIZE + NSK_SIZE + ALPHA_SIZE + RCV_SIZE;

/// Rseed size (random seed for note commitment)
pub const RSEED_SIZE: usize = 32;

/// Hash seed size
pub const HASHSEED_SIZE: usize = 32;

/// Output data length: RCV (32) + Rseed (32)
pub const OUTPUTDATA_SIZE: usize = RCV_SIZE + RSEED_SIZE;

/// Public Key Length for secp256k1
pub const PK_LEN_SECP261K1: usize = 33;

/// Public Key Length for Sapling
pub const PK_LEN_SAPLING: usize = 43;

/// Transparent input size: BIP44-path (20) + script (26) + value (8)
pub const T_IN_INPUT_SIZE: usize = 54;

/// Transparent output size: script (26) + value (8)
pub const T_OUT_INPUT_SIZE: usize = 34;

/// Shielded spend input size: zip32-path (4) + address (43) + value (8)
pub const S_SPEND_INPUT_SIZE: usize = 55;

/// Shielded output input size: address (43) + value (8) + memotype (1) + ovk(32)
pub const S_OUT_INPUT_SIZE: usize = 84;

/// Signature size for transparent and shielded signatures
pub const SIG_SIZE: usize = 64;
