#![allow(
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables,
    clippy::too_many_arguments,
    clippy::result_unit_err,
    deprecated
)]

use blake2b_simd::Params as Blake2bParams;
use group::{cofactor::CofactorCurveAffine, GroupEncoding};
use jubjub::AffinePoint;
use rand::RngCore;
use rand_core::OsRng;
use zcash_primitives::{
    consensus::{self, Parameters, TestNetwork},
    keys::OutgoingViewingKey,
    legacy::Script,
    memo::MemoBytes as Memo,
    merkle_tree::{IncrementalWitness, MerklePath},
    primitives::{PaymentAddress, ProofGenerationKey, Rseed},
    redjubjub::Signature,
    sapling::Node,
    transaction::{
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
};

use data::*;
use errors::Error;
use txbuilder::TransactionMetadata;

mod prover;

pub mod errors;

pub mod data;
pub mod txbuilder;
pub mod txprover;

// Re exports
pub use crate::txbuilder::Builder;
pub use crate::txprover::LocalTxProver;

#[deprecated(since = "0.3.0", note = "use the one in the ledger-zcash crate")]
/// Helper struct to build a transaction using an HSM, piece by piece
///
/// Currently only used in integration tests, hence the deprecation note
pub struct ZcashBuilder<P: Parameters> {
    num_transparent_inputs: usize,
    num_transparent_outputs: usize,
    num_spends: usize,
    num_outputs: usize,
    builder: txbuilder::Builder<P, OsRng>,
    branch: consensus::BranchId,
}
impl ZcashBuilder<TestNetwork> {
    pub fn new_test(fee: u64) -> Self {
        Self::new(fee, TestNetwork)
    }
}

impl<P: Parameters> ZcashBuilder<P> {
    pub fn new(fee: u64, parameters: P) -> Self {
        Self {
            num_transparent_inputs: 0,
            num_transparent_outputs: 0,
            num_spends: 0,
            num_outputs: 0,
            builder: txbuilder::Builder::new_with_fee(parameters, 0, fee),

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
            info.witness,
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
        if info.ovk.is_none() && info.hash_seed.is_none() {
            return Err(Error::InvalidOVKHashSeed);
        }
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

    pub fn build(&mut self, prover: &mut LocalTxProver) -> Result<HsmTxData, Error> {
        self.builder.build(self.branch, prover)
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
