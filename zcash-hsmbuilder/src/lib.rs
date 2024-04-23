/*******************************************************************************
*   (c) 2022-2024 Zondax AG
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
use data::*;
use errors::Error;
use group::{cofactor::CofactorCurveAffine, GroupEncoding};
use jubjub::AffinePoint;
use rand::RngCore;
use rand_core::OsRng;
use txbuilder::SaplingMetadata;
use zcash_primitives::{
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

mod prover;

pub mod errors;

pub mod data;
pub mod txbuilder;
pub mod txprover;

// Re exports
pub use crate::txbuilder::{hsmauth, Builder};
pub use crate::txprover::LocalTxProver;
