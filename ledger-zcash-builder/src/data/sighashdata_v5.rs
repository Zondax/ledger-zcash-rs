/*******************************************************************************
*   (c) 2022 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use std::borrow::Borrow;
use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams, State};
use byteorder::*;
use ff::PrimeField;
use group::GroupEncoding;
use zcash_primitives::{
    consensus,
    transaction::{
        self,
        components::{sapling, sprout, transparent, Amount},
        TransactionData, TxVersion,
    },
};

use crate::{
    data::sighashdata::{
        TransactionDataSighash, TransactionDataSighashV5, SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE,
        SIGHASH_SINGLE,
    },
    hsmauth,
};

/// TxId tree root personalization
const ZCASH_TX_PERSONALIZATION_PREFIX_V5: &[u8; 12] = b"ZcashTxHash_";

// TxId level 1 node personalization
const ZCASH_HEADERS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdHeadersHash";
const ZCASH_TRANSPARENT_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdTranspaHash";
const ZCASH_SAPLING_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSaplingHash";
#[cfg(feature = "zfuture")]
const ZCASH_TZE_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTZE____Hash";

// TxId transparent level 2 node personalization
const ZCASH_PREVOUTS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdOutputsHash";

// TxId sapling level 2 node personalization
const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSSpendsHash";
const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSSpendCHash";
const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSSpendNHash";

const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSOutputHash";
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSOutC__Hash";
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSOutM__Hash";
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxIdSOutN__Hash";

const ZCASH_AUTH_PERSONALIZATION_PREFIX_V5: &[u8; 12] = b"ZTxAuthHash_";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxAuthTransHash";
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION_V5: &[u8; 16] = b"ZTxAuthSapliHash";

const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";

#[derive(Default, Clone, Debug)]
pub struct HeaderPreDigest {
    pub version: [u8; 4],
    pub version_group_id: [u8; 4],
    pub consensus_branch_id: [u8; 4],
    pub lock_time: [u8; 4],
    pub expiry_height: [u8; 4],
}
#[derive(Default, Clone, Debug)]
pub struct TransparentPreDigest {
    pub prevouts_digest: [u8; 32],
    pub sequence_digest: [u8; 32],
    pub outputs_digest: [u8; 32],
}

#[derive(Default, Clone, Debug)]
pub struct SaplingPreDigest {
    pub sapling_spends_digest: [u8; 32],
    pub sapling_outputs_digest: [u8; 32],
    pub value_balance: [u8; 8],
}

fn hasher(personal: &[u8; 16]) -> State {
    Blake2bParams::new()
        .hash_length(32)
        .personal(personal)
        .to_state()
}

/// Sequentially append the serialized value of each transparent input
/// to a hash personalized by ZCASH_PREVOUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn transparent_prevout_hash_v5<TransparentAuth: transparent::Authorization>(
    vin: &[transparent::TxIn<TransparentAuth>]
) -> Blake2bHash {
    let mut h = hasher(ZCASH_PREVOUTS_HASH_PERSONALIZATION_V5);
    for t_in in vin {
        t_in.prevout.write(&mut h).unwrap();
    }
    h.finalize()
}

/// Hash of the little-endian u32 interpretation of the
/// `sequence` values for each TxIn record passed in vin.
pub(crate) fn transparent_sequence_hash_v5<TransparentAuth: transparent::Authorization>(
    vin: &[transparent::TxIn<TransparentAuth>]
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SEQUENCE_HASH_PERSONALIZATION_V5);
    for t_in in vin {
        h.write_u32::<LittleEndian>(t_in.sequence)
            .unwrap();
    }
    h.finalize()
}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by ZCASH_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn transparent_outputs_hash_v5<T: Borrow<transparent::TxOut>>(vout: &[T]) -> Blake2bHash {
    let mut h = hasher(ZCASH_OUTPUTS_HASH_PERSONALIZATION_V5);
    for t_out in vout {
        t_out.borrow().write(&mut h).unwrap();
    }
    h.finalize()
}

/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with
///   ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION_V5
/// * \[(cv, anchor, rk, zkproof)*\] - personalized with
///   ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION_V5
///
/// Then, hash these together personalized by
/// ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION_V5
pub(crate) fn hash_sapling_spends_v5<A: sapling::Authorization>(
    shielded_spends: &[sapling::SpendDescription<A>]
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION_V5);
    if !shielded_spends.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION_V5);
        let mut nh = hasher(ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION_V5);
        for s_spend in shielded_spends {
            // we build the hash of nullifiers separately for compact blocks.
            ch.write_all(s_spend.nullifier.as_ref())
                .unwrap();

            nh.write_all(&s_spend.cv.to_bytes())
                .unwrap();
            nh.write_all(&s_spend.anchor.to_repr())
                .unwrap();
            nh.write_all(&s_spend.rk.0.to_bytes())
                .unwrap();
        }

        let compact_digest = ch.finalize();
        h.write_all(compact_digest.as_bytes())
            .unwrap();
        let noncompact_digest = nh.finalize();
        h.write_all(noncompact_digest.as_bytes())
            .unwrap();
    }
    h.finalize()
}

/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with
///   ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION_V5
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with
///   ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION_V5
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext, zkproof)*\] personalized
///   with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION_V5
///
/// Then, hash these together personalized with
/// ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION_V5
pub(crate) fn hash_sapling_outputs_v5<A>(shielded_outputs: &[sapling::OutputDescription<A>]) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION_V5);
    if !shielded_outputs.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION_V5);
        let mut mh = hasher(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION_V5);
        let mut nh = hasher(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION_V5);
        for s_out in shielded_outputs {
            ch.write_all(s_out.cmu.to_repr().as_ref())
                .unwrap();
            ch.write_all(s_out.ephemeral_key.as_ref())
                .unwrap();
            ch.write_all(&s_out.enc_ciphertext[.. 52])
                .unwrap();

            mh.write_all(&s_out.enc_ciphertext[52 .. 564])
                .unwrap();

            nh.write_all(&s_out.cv.to_bytes())
                .unwrap();
            nh.write_all(&s_out.enc_ciphertext[564 ..])
                .unwrap();
            nh.write_all(&s_out.out_ciphertext)
                .unwrap();
        }

        let ch_fin = ch.finalize();
        let mh_fin = mh.finalize();
        let nh_fin = nh.finalize();

        h.write_all(ch_fin.as_bytes()).unwrap();
        h.write_all(mh_fin.as_bytes()).unwrap();
        h.write_all(nh_fin.as_bytes()).unwrap();
    }
    h.finalize()
}

pub fn hash_orchard_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION).finalize()
}

fn hash_header_txid_data_v5(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: consensus::BranchId,
    lock_time: u32,
    expiry_height: consensus::BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION_V5);

    h.write_u32::<LittleEndian>(version.header())
        .unwrap();
    h.write_u32::<LittleEndian>(version.version_group_id())
        .unwrap();
    h.write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();
    h.write_u32::<LittleEndian>(lock_time)
        .unwrap();
    h.write_u32::<LittleEndian>(expiry_height.into())
        .unwrap();

    h.finalize()
}

// todo: delete, just for testing
fn hash_transparent_txid_data(t_digests: Option<TransparentPreDigest>) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION_V5);
    if let Some(d) = t_digests {
        h.write_all(d.prevouts_digest.as_slice())
            .unwrap();
        h.write_all(d.sequence_digest.as_slice())
            .unwrap();
        h.write_all(d.outputs_digest.as_slice())
            .unwrap();
    }
    h.finalize()
}

fn hash_sapling_txid_data<A: sapling::Authorization>(bundle: Option<&sapling::Bundle<A>>) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION_V5);
    if let Some(b) = bundle {
        h.write_all(hash_sapling_spends_v5(&b.shielded_spends).as_bytes())
            .unwrap();

        h.write_all(hash_sapling_outputs_v5(&b.shielded_outputs).as_bytes())
            .unwrap();

        h.write_all(&b.value_balance.to_i64_le_bytes())
            .unwrap();
    }
    h.finalize()
}

pub fn signature_hash_input_data_v5(
    tx: &TransactionData<hsmauth::Unauthorized>,
    hash_type: u8,
) -> TransactionDataSighash
where
{
    let flag_anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;
    let flag_single = hash_type & SIGHASH_MASK == SIGHASH_SINGLE;
    let flag_none = hash_type & SIGHASH_MASK == SIGHASH_NONE;

    let mut txdata_sighash = TransactionDataSighashV5::default();
    let mut tmp = [0; 8];

    // header_digest = BLAKE2b-256 hash of the following values
    // version || version_group_id || consensus_branch_id || lock_time ||
    // expiry_height
    let header = tx.version().header().to_le_bytes();
    let version_group_id = tx
        .version()
        .version_group_id()
        .to_le_bytes();
    let consensus_branch_id = u32::from(tx.consensus_branch_id()).to_le_bytes();
    let lock_time = tx.lock_time().to_le_bytes();
    let expiry_height = u32::from(tx.expiry_height()).to_le_bytes();

    // header_digest fields
    txdata_sighash.header_pre_digest.version = header;
    txdata_sighash
        .header_pre_digest
        .version_group_id = version_group_id;
    txdata_sighash
        .header_pre_digest
        .consensus_branch_id = consensus_branch_id;
    txdata_sighash
        .header_pre_digest
        .lock_time = lock_time;
    txdata_sighash
        .header_pre_digest
        .expiry_height = expiry_height;

    let binding_in = [].to_vec();
    let vin = match &tx.transparent_bundle() {
        Some(t_tx) => &t_tx.vin,
        None => &binding_in,
    };

    let binding_out = [].to_vec();
    let vout = match &tx.transparent_bundle() {
        Some(t_tx) => &t_tx.vout,
        None => &binding_out,
    };

    // transparent_digest fields
    let mut prevouts_digest = [0u8; 32];
    let mut sequence_digest = [0u8; 32];
    let mut outputs_digest = [0u8; 32];
    prevouts_digest.copy_from_slice(transparent_prevout_hash_v5(vin).as_bytes());
    sequence_digest.copy_from_slice(transparent_sequence_hash_v5(vin).as_bytes());
    outputs_digest.copy_from_slice(transparent_outputs_hash_v5(vout).as_bytes());
    txdata_sighash
        .transparent_pre_digest
        .prevouts_digest = prevouts_digest;
    txdata_sighash
        .transparent_pre_digest
        .sequence_digest = sequence_digest;
    txdata_sighash
        .transparent_pre_digest
        .outputs_digest = outputs_digest;

    let sapling_binding_in = [].to_vec();
    let sapling_binding_out = [].to_vec();
    let (shielded_spends, shielded_outputs, vb) = match &tx.sapling_bundle() {
        Some(z_tx) => (&z_tx.shielded_spends, &z_tx.shielded_outputs, z_tx.value_balance),
        None => (&sapling_binding_in, &sapling_binding_out, Amount::from_u64(0).unwrap()),
    };

    // sapling_digest fields
    let mut sapling_spends_digest = [0u8; 32];
    let mut sapling_outputs_digest = [0u8; 32];
    let mut value_balance = [0u8; 8];

    sapling_spends_digest.copy_from_slice(hash_sapling_spends_v5(shielded_spends).as_bytes());
    sapling_outputs_digest.copy_from_slice(hash_sapling_outputs_v5(shielded_outputs).as_bytes());
    value_balance.copy_from_slice(&vb.to_i64_le_bytes());

    txdata_sighash
        .sapling_pre_digest
        .sapling_spends_digest = sapling_spends_digest;
    txdata_sighash
        .sapling_pre_digest
        .sapling_outputs_digest = sapling_outputs_digest;
    txdata_sighash
        .sapling_pre_digest
        .value_balance = value_balance;

    // empty orchard digest
    txdata_sighash
        .orchard_digest
        .copy_from_slice(hash_orchard_empty().as_bytes());

    TransactionDataSighash::V5(txdata_sighash)
}
