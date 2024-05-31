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
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::*;
use ff::PrimeField;
use group::GroupEncoding;
use zcash_primitives::{
    consensus,
    transaction::{
        self,
        components::{sapling, sprout, transparent},
        TransactionData,
    },
};

use crate::data::sighashdata::{
    TransactionDataSighash, TransactionDataSighashV4, OVERWINTER_VERSION_GROUP_ID, SAPLING_TX_VERSION,
    SAPLING_VERSION_GROUP_ID, SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE,
};
use crate::hsmauth;

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";

macro_rules! write_u32 {
    ($h:expr, $value:expr, $tmp:expr) => {
        // LittleEndian::write_u32(&mut $tmp[..4],$value);
        (&mut $tmp[.. 4])
            .write_u32::<LittleEndian>($value)
            .unwrap();
        $h.copy_from_slice(&$tmp[.. 4]);
    };
}

macro_rules! update_data {
    ($h:expr, $cond:expr, $value:expr) => {
        if $cond {
            $h.copy_from_slice(&$value.as_ref());
        } else {
            $h.copy_from_slice(&[0; 32]);
        }
    };
}

fn prevout_hash_v4<A: transparent::Authorization>(vins: &[transparent::TxIn<A>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vins.len() * 36);
    for t_in in vins {
        t_in.prevout.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sequence_hash_v4<A: transparent::Authorization>(vins: &[transparent::TxIn<A>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vins.len() * 4);
    for t_in in vins {
        data.write_u32::<LittleEndian>(t_in.sequence)
            .unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SEQUENCE_HASH_PERSONALIZATION)
        .hash(&data)
}

fn outputs_hash_v4(vouts: &[transparent::TxOut]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vouts.len() * (4 + 1));
    for t_out in vouts {
        t_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn joinsplits_hash_v4(
    consensus_branch_id: consensus::BranchId,
    joinsplits: &[sprout::JsDescription],
    joinsplit_pubkey: &[u8; 32],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(
        joinsplits.len()
            * if consensus_branch_id.sprout_uses_groth_proofs() {
                1698 // JSDescription with Groth16 proof
            } else {
                1802 // JSDescription with PHGR13 proof
            },
    );
    for js in joinsplits {
        js.write(&mut data).unwrap();
    }
    data.extend_from_slice(joinsplit_pubkey);
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_JOINSPLITS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_spends_hash_v4<A>(shielded_spends: &[sapling::SpendDescription<A>]) -> Blake2bHash
where
    A: sapling::Authorization,
    A::Proof: AsRef<[u8]>,
{
    let mut data = Vec::with_capacity(shielded_spends.len() * 384);
    for s_spend in shielded_spends {
        data.extend_from_slice(&s_spend.cv.to_bytes());
        data.extend_from_slice(s_spend.anchor.to_repr().as_ref());
        data.extend_from_slice(s_spend.nullifier.as_ref());
        s_spend.rk.write(&mut data).unwrap();
        data.extend_from_slice(s_spend.zkproof.as_ref());
    }

    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_outputs_hash_v4(shielded_outputs: &[sapling::OutputDescription<sapling::GrothProofBytes>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(shielded_outputs.len() * 948);
    for s_out in shielded_outputs {
        s_out.write_v4(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

pub fn signature_hash_input_data_v4(
    tx: &TransactionData<hsmauth::Unauthorized>,
    hash_type: u8,
) -> TransactionDataSighash
where
{
    let mut txdata_sighash = TransactionDataSighashV4::default();
    let mut tmp = [0; 8];

    let header = tx.version().header();
    let version_group_id = tx.version().version_group_id();

    write_u32!(txdata_sighash.header, header, tmp);
    write_u32!(txdata_sighash.version_id, version_group_id, tmp);

    // transparent data
    // replace vin and vout with empty slices
    // if we don't have the bundle
    if let Some((vin, vout)) = tx
        .transparent_bundle()
        .map(|b| (b.vin.as_slice(), b.vout.as_slice()))
        .or(Some((&[], &[])))
    {
        update_data!(txdata_sighash.prevoutshash, hash_type & SIGHASH_ANYONECANPAY == 0, prevout_hash_v4(vin)); // true for sighash_all

        update_data!(
            txdata_sighash.sequencehash,
            hash_type & SIGHASH_ANYONECANPAY == 0
                && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
            sequence_hash_v4(vin)
        ); // true for sighash_all

        if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE && (hash_type & SIGHASH_MASK) != SIGHASH_NONE {
            txdata_sighash
                .outputshash
                .copy_from_slice(outputs_hash_v4(vout).as_ref()); // true for sighash all

        // TODO: single output hash? SIGHASH_SINGLE
        } else {
            txdata_sighash
                .outputshash
                .copy_from_slice(&[0; 32]);
        };
    }

    // sprout data
    update_data!(
        txdata_sighash.joinsplitshash,
        !tx.sprout_bundle()
            .map_or(true, |b| b.joinsplits.is_empty()),
        {
            let bundle = tx.sprout_bundle().unwrap();
            joinsplits_hash_v4(tx.consensus_branch_id(), &bundle.joinsplits, &bundle.joinsplit_pubkey)
        }
    );

    // sapling data
    update_data!(
        txdata_sighash.shieldedspendhash,
        !tx.sapling_bundle()
            .map_or(true, |b| b.shielded_spends.is_empty()),
        shielded_spends_hash_v4(
            &tx.sapling_bundle()
                .unwrap()
                .shielded_spends
        )
    );
    update_data!(
        txdata_sighash.shieldedoutputhash,
        !tx.sapling_bundle()
            .map_or(true, |b| b.shielded_outputs.is_empty()),
        shielded_outputs_hash_v4(
            &tx.sapling_bundle()
                .unwrap()
                .shielded_outputs
        )
    );

    write_u32!(txdata_sighash.lock_time, tx.lock_time(), tmp);

    let expiry_height = tx.expiry_height().into();
    write_u32!(txdata_sighash.expiry_height, expiry_height, tmp);

    let sapling_value_balance = tx
        .sapling_bundle()
        .map_or(transaction::components::Amount::zero(), |b| b.value_balance);
    txdata_sighash
        .value_balance
        .copy_from_slice(&sapling_value_balance.to_i64_le_bytes());

    write_u32!(txdata_sighash.hash_type, hash_type as u32, tmp);
    TransactionDataSighash::V4(txdata_sighash)
}
