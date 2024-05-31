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
        TransactionData, TxDigests,
    },
};

use crate::{data::sighashdata_v4, data::sighashdata_v5, hsmauth};

pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_MASK: u8 = 0x1f;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

pub const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;
pub const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;
pub const SAPLING_TX_VERSION: u32 = 4;

#[derive(Clone, Debug)]
pub enum TransactionDataSighash {
    V4(TransactionDataSighashV4),
    V5(TransactionDataSighashV5),
}

impl TransactionDataSighash {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TransactionDataSighash::V4(tx) => tx.to_bytes(),
            TransactionDataSighash::V5(tx) => tx.to_bytes(),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct TransactionDataSighashV4 {
    pub header: [u8; 4],
    pub version_id: [u8; 4],
    pub prevoutshash: [u8; 32],
    pub sequencehash: [u8; 32],
    pub outputshash: [u8; 32],
    pub joinsplitshash: [u8; 32],
    pub shieldedspendhash: [u8; 32],
    pub shieldedoutputhash: [u8; 32],
    pub lock_time: [u8; 4],
    pub expiry_height: [u8; 4],
    pub value_balance: [u8; 8],
    pub hash_type: [u8; 4],
}

impl TransactionDataSighashV4 {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(220);
        data.extend_from_slice(&self.header);
        data.extend_from_slice(&self.version_id);
        data.extend_from_slice(&self.prevoutshash);
        data.extend_from_slice(&self.sequencehash);
        data.extend_from_slice(&self.outputshash);
        data.extend_from_slice(&self.joinsplitshash);
        data.extend_from_slice(&self.shieldedspendhash);
        data.extend_from_slice(&self.shieldedoutputhash);
        data.extend_from_slice(&self.lock_time);
        data.extend_from_slice(&self.expiry_height);
        data.extend_from_slice(&self.value_balance);
        data.extend_from_slice(&self.hash_type);
        data
    }
}

// todo: change this to a layer down the tree (more details)
#[derive(Default, Clone, Debug)]
pub struct TransactionDataSighashV5 {
    pub header_pre_digest: sighashdata_v5::HeaderPreDigest,
    pub transparent_pre_digest: sighashdata_v5::TransparentPreDigest,
    pub sapling_pre_digest: sighashdata_v5::SaplingPreDigest,
    pub orchard_digest: [u8; 32],
}

impl TransactionDataSighashV5 {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(128);
        // header_digest fields
        data.extend_from_slice(&self.header_pre_digest.version);
        data.extend_from_slice(&self.header_pre_digest.version_group_id);
        data.extend_from_slice(
            &self
                .header_pre_digest
                .consensus_branch_id,
        );
        data.extend_from_slice(&self.header_pre_digest.lock_time);
        data.extend_from_slice(&self.header_pre_digest.expiry_height);
        // transparent_digest fields
        data.extend_from_slice(
            &self
                .transparent_pre_digest
                .prevouts_digest,
        );
        data.extend_from_slice(
            &self
                .transparent_pre_digest
                .sequence_digest,
        );
        data.extend_from_slice(
            &self
                .transparent_pre_digest
                .outputs_digest,
        );
        // sapling_digest fields
        data.extend_from_slice(
            &self
                .sapling_pre_digest
                .sapling_spends_digest,
        );
        data.extend_from_slice(
            &self
                .sapling_pre_digest
                .sapling_outputs_digest,
        );
        data.extend_from_slice(&self.sapling_pre_digest.value_balance);
        // orchard_digest
        data.extend_from_slice(&self.orchard_digest);

        data
    }
}

#[derive(PartialEq)]
enum SigHashVersion {
    Sprout,
    Overwinter,
    Sapling,
    NU5,
}

impl SigHashVersion {
    //noinspection RsNonExhaustiveMatch
    fn from_tx<A: transaction::Authorization>(tx: &TransactionData<A>) -> Self {
        use zcash_primitives::transaction::TxVersion;
        match tx.version() {
            TxVersion::Sprout(_) => SigHashVersion::Sprout,
            TxVersion::Overwinter => SigHashVersion::Overwinter,
            TxVersion::Sapling => SigHashVersion::Sapling,
            TxVersion::Zip225 => SigHashVersion::NU5,
        }
    }
}

pub fn signature_hash_input_data(
    tx: &TransactionData<hsmauth::Unauthorized>,
    hash_type: u8,
) -> TransactionDataSighash
where
{
    let sig_version = SigHashVersion::from_tx(tx);

    match sig_version {
        SigHashVersion::NU5 => sighashdata_v5::signature_hash_input_data_v5(tx, hash_type),
        SigHashVersion::Overwinter | SigHashVersion::Sapling => {
            sighashdata_v4::signature_hash_input_data_v4(tx, hash_type)
        },
        SigHashVersion::Sprout => unimplemented!(),
    }
}
