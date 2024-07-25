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
//! This module contains many of the data structures used in the crate and
//! in conjunction with the HSM builder

mod neon_bridge;
use neon_bridge::*;

pub mod sighashdata;
pub mod sighashdata_v4;
pub mod sighashdata_v5;
use serde::{Deserialize, Serialize};
use sighashdata::TransactionDataSighash;
use zcash_primitives::{
    keys::OutgoingViewingKey,
    legacy::Script,
    memo::MemoBytes as Memo,
    merkle_tree::MerklePath,
    sapling::{redjubjub::Signature, Node, PaymentAddress, ProofGenerationKey, Rseed},
    transaction::components::{Amount, OutPoint},
};

use crate::{
    errors::Error,
    txbuilder::{NullifierInput, OutputDescription, SpendDescription, TransparentScriptData},
};

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
    pub fn to_hsm_bytes(&self) -> Vec<u8> {
        let mut data =
            vec![self.t_in.len() as u8, self.t_out.len() as u8, self.s_spend.len() as u8, self.s_output.len() as u8];

        for info in self.t_in.iter() {
            for p in info.path.iter() {
                data.extend_from_slice(&p.to_le_bytes());
            }
            info.address.write(&mut data).unwrap();
            data.extend_from_slice(&info.value.to_i64_le_bytes());
        }

        for info in self.t_out.iter() {
            info.address.write(&mut data).unwrap();
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

        data
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
    // 26
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount, // 8
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
    #[serde(deserialize_with = "merkle_path_deserialize")]
    pub witness: MerklePath<Node>,
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
    pub transparent_sigs: Vec<secp256k1::ecdsa::Signature>,
    #[serde(deserialize_with = "s_sig_deserialize")]
    pub spend_sigs: Vec<Signature>,
}
