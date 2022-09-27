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
use zcash::primitives::{
    consensus::{self, Parameters, TestNetwork},
    keys::OutgoingViewingKey,
    legacy::Script,
    memo::MemoBytes as Memo,
    merkle_tree::{IncrementalWitness, MerklePath},
    sapling::{redjubjub::Signature, Node, PaymentAddress, ProofGenerationKey, Rseed},
    transaction::{
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
};

pub(crate) mod zcash;

use data::*;
use errors::Error;
use txbuilder::SaplingMetadata;

mod prover;

pub mod errors;

pub mod data;
pub mod txbuilder;
pub mod txprover;

// Re exports
pub use crate::txbuilder::{hsmauth, Builder};
pub use crate::txprover::LocalTxProver;
