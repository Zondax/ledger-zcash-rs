use zcash_primitives::legacy::{Script, TransparentAddress};

///! Helpers to update to latest crates.
/// this should eventually go away


/// Minimal subset of script opcodes.
enum OpCode {
    // push value
    // PushData1 = 0x4c,
    // PushData2 = 0x4d,
    // PushData4 = 0x4e,

    // stack ops
    Dup = 0x76,

    // bit logic
    Equal = 0x87,
    EqualVerify = 0x88,

    // crypto
    Hash160 = 0xa9,
    CheckSig = 0xac,
}

pub fn script_to_address(script: &Script) -> Option<TransparentAddress> {
    if script.0.len() == 25
        && script.0[0..3] == [OpCode::Dup as u8, OpCode::Hash160 as u8, 0x14]
        && script.0[23..25] == [OpCode::EqualVerify as u8, OpCode::CheckSig as u8]
    {
        let mut hash = [0; 20];
        hash.copy_from_slice(&script.0[3..23]);
        Some(TransparentAddress::PublicKey(hash))
    } else if script.0.len() == 23
        && script.0[0..2] == [OpCode::Hash160 as u8, 0x14]
        && script.0[22] == OpCode::Equal as u8
    {
        let mut hash = [0; 20];
        hash.copy_from_slice(&script.0[2..22]);
        Some(TransparentAddress::Script(hash))
    } else {
        None
    }
}