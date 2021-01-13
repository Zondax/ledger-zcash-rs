#![allow(
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables,
    clippy::too_many_arguments,
    clippy::result_unit_err
)]

extern crate hex;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;

use blake2b_simd::Params as Blake2bParams;
use group::{cofactor::CofactorCurveAffine, GroupEncoding};
use jubjub::AffinePoint;
use rand::RngCore;
use rand_core::OsRng;
use zcash_primitives::consensus;
use zcash_primitives::consensus::TestNetwork;
use zcash_primitives::keys::OutgoingViewingKey;
use zcash_primitives::legacy::Script;
use zcash_primitives::merkle_tree::IncrementalWitness;
use zcash_primitives::note_encryption::Memo;
use zcash_primitives::primitives::{PaymentAddress, ProofGenerationKey, Rseed};
use zcash_primitives::redjubjub::Signature;
use zcash_primitives::sapling::Node;
use zcash_primitives::transaction::components::{Amount, OutPoint, TxOut};
use zcash_primitives::transaction::Transaction;

use crate::errors::Error;
use crate::neon_bridge::*;
use crate::sighashdata::TransactionDataSighash;
use crate::txbuilder::{
    NullifierInput, OutputDescription, SpendDescription, TransactionMetadata, TransparentScriptData,
};
use crate::txprover::LocalTxProver;

pub mod errors;
mod neon_bridge;
mod prover;
mod sighashdata;
pub mod txbuilder;
pub mod txprover;

#[derive(Debug, Deserialize)]
pub struct TinData {
    pub path: [u32; 5],
    #[serde(deserialize_with = "script_deserialize")]
    pub address: Script,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
}

#[derive(Debug, Deserialize)]
pub struct ToutData {
    #[serde(deserialize_with = "script_deserialize")]
    pub address: Script,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
}

#[derive(Debug, Deserialize)]
pub struct ShieldedSpendData {
    pub path: u32,
    #[serde(deserialize_with = "s_address_deserialize")]
    pub address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
}

#[derive(Debug, Deserialize)]
pub struct ShieldedOutputData {
    #[serde(deserialize_with = "s_address_deserialize")]
    pub address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
    pub memo_type: u8,
    #[serde(deserialize_with = "ovk_deserialize")]
    pub ovk: Option<OutgoingViewingKey>,
}

#[derive(Debug, Deserialize)]
pub struct InitData {
    pub t_in: Vec<TinData>,
    pub t_out: Vec<ToutData>,
    pub s_spend: Vec<ShieldedSpendData>,
    pub s_output: Vec<ShieldedOutputData>,
}

impl InitData {
    pub fn to_hsm_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();

        data.push(self.t_in.len() as u8);
        data.push(self.t_out.len() as u8);
        data.push(self.s_spend.len() as u8);
        data.push(self.s_output.len() as u8);

        for info in self.t_in.iter() {
            for p in info.path.iter() {
                data.extend_from_slice(&p.to_le_bytes());
            }
            info.address.write(&mut data)?;
            data.extend_from_slice(&info.value.to_i64_le_bytes());
        }

        for info in self.t_out.iter() {
            info.address.write(&mut data)?;
            data.extend_from_slice(&info.value.to_i64_le_bytes());
        }

        for info in self.s_spend.iter() {
            data.extend_from_slice(&info.path.to_le_bytes());
            data.extend_from_slice(&info.address.to_bytes());
            data.extend_from_slice(&info.value.to_i64_le_bytes());
        }

        for info in self.s_output.iter() {
            data.extend_from_slice(&info.address.to_bytes());
            data.extend_from_slice(&info.value.to_i64_le_bytes());
            data.push(info.memo_type);
            if info.ovk.is_some() {
                data.push(0x01);
                data.extend_from_slice(&info.ovk.unwrap().0);
            } else {
                data.push(0x00);
                data.extend_from_slice(&[0u8; 32]);
            }
        }
        Ok(data)
    }
}

pub struct HsmTxData {
    pub t_script_data: Vec<TransparentScriptData>,
    pub s_spend_old_data: Vec<NullifierInput>,
    pub s_spend_new_data: Vec<SpendDescription>,
    pub s_output_data: Vec<OutputDescription>,
    pub tx_hash_data: TransactionDataSighash,
}

impl HsmTxData {
    pub fn to_hsm_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        for t_data in self.t_script_data.iter() {
            t_data.write(&mut data)?;
        }
        for spend_old_data in self.s_spend_old_data.iter() {
            spend_old_data.write(&mut data)?;
        }
        for spend_new_data in self.s_spend_new_data.iter() {
            spend_new_data.write(&mut data)?;
        }
        for output_data in self.s_output_data.iter() {
            output_data.write(&mut data)?;
        }
        data.extend_from_slice(&self.tx_hash_data.to_bytes());
        Ok(data)
    }
}

pub struct ZcashBuilder {
    num_transparent_inputs: usize,
    num_transparent_outputs: usize,
    num_spends: usize,
    num_outputs: usize,
    builder: txbuilder::Builder<TestNetwork, OsRng>,
    branch: consensus::BranchId,
}

#[derive(Debug, Deserialize)]
pub struct TransparentInputBuilderInfo {
    #[serde(deserialize_with = "outpoint_deserialize")]
    pub outp: OutPoint,
    #[serde(deserialize_with = "t_pk_deserialize")]
    pub pk: secp256k1::PublicKey,
    #[serde(deserialize_with = "script_deserialize")]
    pub address: Script,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
}

#[derive(Debug, Deserialize)]
pub struct TransparentOutputBuilderInfo {
    #[serde(deserialize_with = "script_deserialize")]
    pub address: Script,
    //26
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount, //8
}

#[derive(Deserialize)]
pub struct SpendBuilderInfo {
    #[serde(deserialize_with = "pgk_deserialize")]
    pub proofkey: ProofGenerationKey,
    #[serde(deserialize_with = "fr_deserialize")]
    pub rcv: jubjub::Fr,
    #[serde(deserialize_with = "fr_deserialize")]
    pub alpha: jubjub::Fr,
    #[serde(deserialize_with = "s_address_deserialize")]
    pub address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
    #[serde(deserialize_with = "witness_deserialize")]
    pub witness: IncrementalWitness<Node>,
    #[serde(deserialize_with = "rseed_deserialize")]
    pub rseed: Rseed,
}

/// An outgoing viewing key
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HashSeed(pub [u8; 32]);

#[derive(Debug, Deserialize)]
pub struct OutputBuilderInfo {
    #[serde(deserialize_with = "fr_deserialize")]
    pub rcv: jubjub::Fr,
    #[serde(deserialize_with = "rseed_deserialize")]
    pub rseed: Rseed,
    #[serde(deserialize_with = "ovk_deserialize")]
    pub ovk: Option<OutgoingViewingKey>,
    #[serde(deserialize_with = "s_address_deserialize")]
    pub address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
    #[serde(deserialize_with = "memo_deserialize")]
    pub memo: Option<Memo>,
    #[serde(deserialize_with = "hashseed_deserialize")]
    pub hash_seed: Option<HashSeed>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionSignatures {
    #[serde(deserialize_with = "t_sig_deserialize")]
    pub transparent_sigs: Vec<secp256k1::Signature>,
    #[serde(deserialize_with = "s_sig_deserialize")]
    pub spend_sigs: Vec<Signature>,
}

impl ZcashBuilder {
    pub fn new(fee: u64) -> ZcashBuilder {
        ZcashBuilder {
            num_transparent_inputs: 0,
            num_transparent_outputs: 0,
            num_spends: 0,
            num_outputs: 0,
            builder: txbuilder::Builder::<TestNetwork, OsRng>::new_with_fee(0, fee),
            branch: consensus::BranchId::Sapling,
        }
    }

    pub fn add_transparent_input(
        &mut self,
        info: TransparentInputBuilderInfo,
    ) -> Result<(), Error> {
        let coin = TxOut {
            value: info.value,
            script_pubkey: info.address,
        };
        let r = self.builder.add_transparent_input(info.pk, info.outp, coin);
        if r.is_ok() {
            self.num_transparent_inputs += 1;
        }
        r
    }

    pub fn add_transparent_output(
        &mut self,
        info: TransparentOutputBuilderInfo,
    ) -> Result<(), Error> {
        let r = self
            .builder
            .add_transparent_output(info.address, info.value);
        if r.is_ok() {
            self.num_transparent_outputs += 1;
        }
        r
    }

    pub fn add_sapling_spend(&mut self, info: SpendBuilderInfo) -> Result<(), Error> {
        let note = info
            .address
            .create_note(u64::from(info.value), info.rseed)
            .unwrap();

        let r = self.builder.add_sapling_spend(
            *info.address.diversifier(),
            note,
            info.witness.path().unwrap(),
            info.alpha,
            info.proofkey,
            info.rcv,
        );
        if r.is_ok() {
            self.num_spends += 1;
        }
        r
    }

    pub fn add_sapling_output(&mut self, info: OutputBuilderInfo) -> Result<(), Error> {
        let r = self.builder.add_sapling_output(
            info.ovk,
            info.address,
            info.value,
            info.memo,
            info.rcv,
            info.rseed,
            info.hash_seed,
        );
        if r.is_ok() {
            self.num_outputs += 1;
        }
        r
    }

    pub fn build(&mut self, prover: &mut LocalTxProver) -> Result<Vec<u8>, Error> {
        let r = self.builder.build(self.branch, prover);
        r.map(|v| v.to_hsm_bytes())?
    }

    pub fn add_signatures(&mut self, input: TransactionSignatures) -> Result<(), Error> {
        self.builder
            .add_signatures_transparant(input.transparent_sigs, self.branch)?;
        self.builder.add_signatures_spend(input.spend_sigs)
    }

    pub fn finalize(mut self) -> Result<(Transaction, TransactionMetadata), Error> {
        self.builder.finalize()
    }

    pub fn finalize_js(&mut self) -> Result<Vec<u8>, Error> {
        self.builder.finalize_js()
    }
}
