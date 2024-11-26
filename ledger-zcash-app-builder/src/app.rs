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
//! Support library for Zcash Ledger Nano S/X apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

use std::{convert::TryFrom, path::Path};

use ledger_transport::Exchange;
use ledger_zcash::app::ZcashApp;
use ledger_zcash_chain_builder::data::{SaplingInData, SaplingOutData};
use ledger_zcash_chain_builder::{
    data::{
        HashSeed, HsmTxData, InitData, OutputBuilderInfo, SpendBuilderInfo, TinData, ToutData,
        TransparentInputBuilderInfo, TransparentOutputBuilderInfo,
    },
    txbuilder::SaplingMetadata,
};
use ledger_zondax_generic::LedgerAppError;
use zcash_primitives::{
    consensus::{self, Parameters},
    keys::OutgoingViewingKey,
    legacy::Script,
    memo::MemoBytes as Memo,
    merkle_tree::MerklePath,
    sapling::{Diversifier, Node, Note, PaymentAddress, ProofGenerationKey, Rseed},
    transaction::{
        components::{Amount, OutPoint},
        Transaction, TxVersion,
    },
};
use zx_bip44::BIP44Path;

use crate::builder::{Builder, BuilderError};
use crate::config::*;

type PublicKeySecp256k1 = [u8; PK_LEN_SECP261K1];

/// Ledger App
pub struct ZcashAppBuilder<E> {
    /// -
    pub app: ZcashApp<E>,
}

impl<E> ZcashAppBuilder<E> {
    /// Connect to the Ledger App
    pub const fn new(apdu_transport: E) -> Self {
        Self { app: ZcashApp::new(apdu_transport) }
    }
}

/// Data needed to handle transparent input for sapling transaction
/// Contains information needed for both ledger and builder
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct DataTransparentInput {
    /// BIP44 path for transparent input key derivation
    pub path: BIP44Path,
    /// Public key belonging to the secret key (of the BIP44 path)
    pub pk: secp256k1::PublicKey,
    /// UTXO of transparent input
    pub prevout: OutPoint,
    /// Script of transparent input
    pub script: Script,
    /// Value of transparent input
    pub value: Amount,
}

impl DataTransparentInput {
    /// Takes the fields needed to send to the ledger
    pub fn to_init_data(&self) -> TinData {
        TinData { path: self.path.0, address: self.script.clone(), value: self.value }
    }

    /// Takes the fields needed to send to the builder
    pub fn to_builder_data(&self) -> TransparentInputBuilderInfo {
        TransparentInputBuilderInfo {
            outp: self.prevout.clone(),
            pk: self.pk,
            address: self.script.clone(),
            value: self.value,
        }
    }
}

/// Data needed to handle transparent output for sapling transaction
#[derive(Debug)]
pub struct DataTransparentOutput {
    /// The transparent output value
    pub value: Amount,
    /// The transparent output script
    pub script_pubkey: Script,
}

impl DataTransparentOutput {
    /// Decouples this struct to send to ledger
    pub fn to_init_data(&self) -> ToutData {
        ToutData { address: self.script_pubkey.clone(), value: self.value }
    }

    /// Decouples this struct to send to builder
    pub fn to_builder_data(&self) -> TransparentOutputBuilderInfo {
        TransparentOutputBuilderInfo { address: self.script_pubkey.clone(), value: self.value }
    }
}

/// Data needed to handle shielded spend for sapling transaction
#[derive(Clone, Debug)]
pub struct DataShieldedSpend {
    /// ZIP32 path (last non-constant value)
    pub path: u32,
    /// Spend note
    /// Note: only Rseed::AfterZip202 supported
    pub note: Note,
    /// Diversifier of the address of the note
    pub diversifier: Diversifier,
    /// Witness for the spend note
    pub witness: MerklePath<Node>,
}

impl DataShieldedSpend {
    /// Retrieve the PaymentAddress that the note was paid to
    pub fn address(&self) -> PaymentAddress {
        PaymentAddress::from_parts(self.diversifier, self.note.pk_d)
            // if we have a note then pk_d is not the identity
            .expect("pk_d not identity")
    }

    /// Take the fields needed to send to ledger
    pub fn to_init_data(&self) -> SaplingInData {
        SaplingInData {
            path: self.path,
            address: self.address(),
            // if we have a note the amount is in range
            value: Amount::from_u64(self.note.value).unwrap(),
        }
    }

    /// Take the fields plus additional inputs to send to builder
    pub fn to_builder_data(
        &self,
        spendinfo: (ProofGenerationKey, jubjub::Fr, jubjub::Fr),
    ) -> SpendBuilderInfo {
        let init_data = self.to_init_data();

        SpendBuilderInfo {
            proofkey: spendinfo.0,
            rcv: spendinfo.1,
            alpha: spendinfo.2,
            address: init_data.address,
            value: init_data.value,
            witness: self.witness.clone(),
            rseed: self.note.rseed,
        }
    }
}

/// Data needed to handle shielded output for sapling transaction
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct DataShieldedOutput {
    /// address of shielded output
    #[educe(Debug(method = "crate::zcash::payment_address_bytes_fmt"))]
    pub address: PaymentAddress,
    /// value send to that address
    pub value: Amount,
    /// Optional outgoing viewing key
    pub ovk: Option<OutgoingViewingKey>,
    /// Optional Memo
    pub memo: Option<Memo>,
}

impl DataShieldedOutput {
    /// Constructs the fields needed to send to ledger
    /// Ledger only checks memo-type, not the content
    pub fn to_init_data(&self) -> SaplingOutData {
        SaplingOutData {
            address: self.address.clone(),
            value: self.value,
            memo_type: self
                .memo
                .as_ref()
                .map(|v| v.as_array()[0])
                .unwrap_or(0xf6),
            ovk: self.ovk,
        }
    }

    /// Take the fields plus additional inputs to send to builder
    pub fn to_builder_data(
        &self,
        outputinfo: (jubjub::Fr, Rseed, Option<HashSeed>),
    ) -> OutputBuilderInfo {
        OutputBuilderInfo {
            rcv: outputinfo.0,
            rseed: outputinfo.1,
            ovk: self.ovk,
            address: self.address.clone(),
            value: self.value,
            memo: self.memo.clone(),
            hash_seed: outputinfo.2,
        }
    }
}

/// Data needed for sapling transaction
#[derive(Debug)]
pub struct DataInput {
    /// transaction fee.
    /// Note: Ledger only supports fees of 10000 or 1000
    /// Note: Ledger only supports vectors up to length 5 at the moment for all
    /// below vectors
    pub txfee: u64,
    /// A vector of transparent inputs
    pub vec_tin: Vec<DataTransparentInput>,
    /// A vector of transparent outputs
    pub vec_tout: Vec<DataTransparentOutput>,
    /// A vector of shielded spends
    pub vec_sspend: Vec<DataShieldedSpend>,
    /// A vector of shielded outputs
    pub vec_soutput: Vec<DataShieldedOutput>,
}

impl DataInput {
    /// Prepares the data to send to the ledger
    pub fn to_inittx_data(&self) -> InitData {
        let mut t_in = Vec::with_capacity(self.vec_tin.len() * T_IN_INPUT_SIZE);
        for info in self.vec_tin.iter() {
            t_in.push(info.to_init_data());
        }

        let mut t_out = Vec::with_capacity(self.vec_tout.len() * T_OUT_INPUT_SIZE);
        for info in self.vec_tout.iter() {
            t_out.push(info.to_init_data());
        }

        let mut s_spend = Vec::with_capacity(self.vec_sspend.len() * S_SPEND_INPUT_SIZE);
        for info in self.vec_sspend.iter() {
            s_spend.push(info.to_init_data());
        }

        let mut s_output = Vec::with_capacity(self.vec_soutput.len() * S_OUT_INPUT_SIZE);
        for info in self.vec_soutput.iter() {
            s_output.push(info.to_init_data());
        }

        InitData { t_in, t_out, s_spend, s_output }
    }
}

// type PublicKeySapling = [u8; PK_LEN_SAPLING];

/// Zcash unshielded address
#[allow(dead_code)]
pub struct AddressUnshielded {
    /// Public Key
    pub public_key: PublicKeySecp256k1,
    /// Address (exposed as SS58)
    pub address: String,
}

/// Zcash shielded address
#[allow(dead_code)]
pub struct AddressShielded {
    /// Public Key
    pub public_key: PaymentAddress,
    /// Address (exposed as SS58)
    pub address: String,
}

impl<E> ZcashAppBuilder<E>
where
    E: Exchange + Send + Sync,
    E::Error: std::error::Error,
{
    /// Initiates a transaction in the ledger
    pub async fn init_tx(
        &self,
        data: InitData,
    ) -> Result<[u8; SHA256_DIGEST_SIZE], LedgerAppError<E::Error>> {
        let data = data.to_hsm_bytes();

        self.app.init_tx(data).await
    }

    /// Initiates a transaction in the ledger
    pub async fn checkandsign(
        &self,
        data: HsmTxData,
        tx_version: TxVersion,
    ) -> Result<[u8; 32], LedgerAppError<E::Error>> {
        // this is actually infallible
        let data = data.to_hsm_bytes().unwrap();
        let hex_tx_version = match tx_version {
            TxVersion::Zip225 => 0x05,
            TxVersion::Sapling => 0x04,
            _ => 0u8,
        };

        self.app
            .checkandsign(data, hex_tx_version)
            .await
    }

    /// Does a complete transaction in the ledger
    pub async fn do_transaction<P: Parameters + Send + Sync>(
        &self,
        input: DataInput,
        parameters: P,
        branch: consensus::BranchId,
        tx_version: Option<TxVersion>,
        target_height: u32,
    ) -> Result<(Transaction, SaplingMetadata), LedgerAppError<E::Error>> {
        log::info!("adding transaction data to builder");
        let fee = input.txfee;

        let builder: Builder =
            Builder::try_from(input).map_err(|e: BuilderError| LedgerAppError::AppSpecific(0, e.to_string()))?;

        let prover = ledger_zcash_chain_builder::txprover::LocalTxProver::new(
            Path::new("../params/sapling-spend.params"),
            Path::new("../params/sapling-output.params"),
        );
        log::info!("building the transaction");

        // Set up a channel to recieve updates on the progress of building the
        // transaction.
        let (tx, _) = std::sync::mpsc::channel();

        let txdata = builder
            .build(self, parameters, &prover, fee, &mut rand_core::OsRng, target_height, branch, tx_version, Some(tx))
            .await
            .map_err(|e| LedgerAppError::AppSpecific(0, e.to_string()))?;

        log::info!("transaction built and complete");
        Ok(txdata)
    }
}
