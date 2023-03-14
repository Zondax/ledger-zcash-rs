/*******************************************************************************
*   (c) 2022 Zondax GmbH
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

use std::{convert::TryFrom, path::Path, str};

use ledger_transport::{APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{
    App, AppExt, AppInfo, ChunkPayloadType, DeviceInfo, LedgerAppError, Version,
};

use crate::zcash::primitives::{
    consensus::{self, Parameters},
    keys::OutgoingViewingKey,
    legacy::Script,
    memo::MemoBytes as Memo,
    merkle_tree::MerklePath,
    sapling::{
        redjubjub::Signature, Diversifier, Node, Note, Nullifier, PaymentAddress,
        ProofGenerationKey, Rseed,
    },
    transaction::{
        components::{Amount, OutPoint},
        Transaction,
    },
};

use zcash_hsmbuilder::{
    data::{
        HashSeed, HsmTxData, InitData, OutputBuilderInfo, ShieldedOutputData, ShieldedSpendData,
        SpendBuilderInfo, TinData, ToutData, TransparentInputBuilderInfo,
        TransparentOutputBuilderInfo,
    },
    txbuilder::SaplingMetadata,
};

use byteorder::{LittleEndian, WriteBytesExt};
use group::GroupEncoding;
use sha2::{Digest, Sha256};
use zx_bip44::BIP44Path;

use crate::builder::{Builder, BuilderError};

const INS_GET_IVK: u8 = 0xf0;
const INS_GET_OVK: u8 = 0xf1;
const INS_GET_NF: u8 = 0xf2;
const INS_INIT_TX: u8 = 0xa0;
const INS_EXTRACT_SPEND: u8 = 0xa1;
const INS_EXTRACT_OUTPUT: u8 = 0xa2;
const INS_CHECKANDSIGN: u8 = 0xa3;
const INS_EXTRACT_SPENDSIG: u8 = 0xa4;
const INS_EXTRACT_TRANSSIG: u8 = 0xa5;
const INS_GET_DIV_LIST: u8 = 0x09;

const CLA: u8 = 0x85;
const INS_GET_ADDR_SECP256K1: u8 = 0x01;
const INS_GET_ADDR_SAPLING: u8 = 0x11;
const INS_GET_ADDR_SAPLING_DIV: u8 = 0x10;

///Lenght of diversifier index
const DIV_INDEX_SIZE: usize = 11;
///Diversifier length
const DIV_SIZE: usize = 11;
///get div list returns 20 diversifiers
const DIV_LIST_SIZE: usize = 220;

///OVK size
const OVK_SIZE: usize = 32;

///IVK size
const IVK_SIZE: usize = 32;

///NF size
const NF_SIZE: usize = 32;

///note commitment size
const NOTE_COMMITMENT_SIZE: usize = 32;

///sha256 digest size
const SHA256_DIGEST_SIZE: usize = 32;

///AK size
const AK_SIZE: usize = 32;

///NSK size
const NSK_SIZE: usize = 32;

///ALPHA size
const ALPHA_SIZE: usize = 32;

///RCV size
const RCV_SIZE: usize = 32;

///Spenddata length: AK (32) + NSK (32) + Alpha(32) + RCV (32)
const SPENDDATA_SIZE: usize = AK_SIZE + NSK_SIZE + ALPHA_SIZE + RCV_SIZE;

///RCM size
const RSEED_SIZE: usize = 32;

///hashseed size
const HASHSEED_SIZE: usize = 32;

///outputdata length: RCV (32) + RCM (32) +
const OUTPUTDATA_SIZE: usize = RCV_SIZE + RSEED_SIZE;

///outputdata length: RCV (32) + RCM (32) + Hashseed (32)
const OUTPUTDATA_HASHSEED_SIZE: usize = RCV_SIZE + RSEED_SIZE + HASHSEED_SIZE;

/// Public Key Length (secp256k1)
pub const PK_LEN_SECP261K1: usize = 33;

/// Public Key Length (sapling)
pub const PK_LEN_SAPLING: usize = 43;

//T_IN input size: BIP44-path (20) + script (26) + value (8)
const T_IN_INPUT_SIZE: usize = 54;

//T_OUT input size: script (26) + value (8)
const T_OUT_INPUT_SIZE: usize = 34;

//S_SPEND input size: zip32-path (4) + address (43) + value (8)
const S_SPEND_INPUT_SIZE: usize = 55;

//S_SPEND input size: address (43) + value (8) + memotype (1) + ovk(32)
const S_OUT_INPUT_SIZE: usize = 84;

//Signature size for transparent and shielded signatures
const SIG_SIZE: usize = 64;

type PublicKeySecp256k1 = [u8; PK_LEN_SECP261K1];

/// Ledger App
pub struct ZcashApp<E> {
    apdu_transport: E,
}

impl<E: Exchange> App for ZcashApp<E> {
    const CLA: u8 = CLA;
}

impl<E> ZcashApp<E> {
    /// Connect to the Ledger App
    pub const fn new(apdu_transport: E) -> Self {
        Self { apdu_transport }
    }

    const fn cla(&self) -> u8 {
        CLA
    }
}

///Data needed to handle transparent input for sapling transaction
///Contains information needed for both ledger and builder
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct DataTransparentInput {
    ///BIP44 path for transparent input key derivation
    pub path: BIP44Path,
    ///Public key belonging to the secret key (of the BIP44 path)
    #[educe(Debug(trait = "std::fmt::Display"))]
    pub pk: secp256k1::PublicKey,
    ///UTXO of transparent input
    pub prevout: OutPoint,
    ///Script of transparent input
    pub script: Script,
    ///Value of transparent input
    pub value: Amount,
}

impl DataTransparentInput {
    ///Takes the fields needed to send to the ledger
    pub fn to_init_data(&self) -> TinData {
        TinData {
            path: self.path.0,
            address: self.script.clone(),
            value: self.value,
        }
    }

    ///Takes the fields needed to send to the builder
    pub fn to_builder_data(&self) -> TransparentInputBuilderInfo {
        TransparentInputBuilderInfo {
            outp: self.prevout.clone(),
            pk: self.pk,
            address: self.script.clone(),
            value: self.value,
        }
    }
}

///Data needed to handle transparent output for sapling transaction
#[derive(Debug)]
pub struct DataTransparentOutput {
    ///The transparent output value
    pub value: Amount,
    ///The transparent output script
    pub script_pubkey: Script,
}

impl DataTransparentOutput {
    ///Decouples this struct to send to ledger
    pub fn to_init_data(&self) -> ToutData {
        ToutData {
            address: self.script_pubkey.clone(),
            value: self.value,
        }
    }

    ///Decouples this struct to send to builder
    pub fn to_builder_data(&self) -> TransparentOutputBuilderInfo {
        TransparentOutputBuilderInfo {
            address: self.script_pubkey.clone(),
            value: self.value,
        }
    }
}

///Data needed to handle shielded spend for sapling transaction
#[derive(Clone, Debug)]
pub struct DataShieldedSpend {
    ///ZIP32 path (last non-constant value)
    pub path: u32,
    /// Spend note
    /// Note: only Rseed::AfterZip202 supported
    pub note: Note,
    /// Diversifier of the address of the note
    pub diversifier: Diversifier,
    ///Witness for the spend note
    pub witness: MerklePath<Node>,
}

impl DataShieldedSpend {
    /// Reetrieve the PaymentAddress that the note was paid to
    pub fn address(&self) -> PaymentAddress {
        PaymentAddress::from_parts(self.diversifier, self.note.pk_d)
            //if we have a note then pk_d is not the identity
            .expect("pk_d not identity")
    }

    ///Take the fields needed to send to ledger
    pub fn to_init_data(&self) -> ShieldedSpendData {
        ShieldedSpendData {
            path: self.path,
            address: self.address(),
            //if we have a note the amount is in range
            value: Amount::from_u64(self.note.value).unwrap(),
        }
    }

    ///Take the fields plus additional inputs to send to builder
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

///Data needed to handle shielded output for sapling transaction
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct DataShieldedOutput {
    ///address of shielded output
    #[educe(Debug(method = "crate::zcash::payment_address_bytes_fmt"))]
    pub address: PaymentAddress,
    ///value send to that address
    pub value: Amount,
    ///Optional outgoing viewing key
    pub ovk: Option<OutgoingViewingKey>,
    ///Optional Memo
    pub memo: Option<Memo>,
}

impl DataShieldedOutput {
    ///Constructs the fields needed to send to ledger
    ///Ledger only checks memo-type, not the content
    pub fn to_init_data(&self) -> ShieldedOutputData {
        ShieldedOutputData {
            address: self.address.clone(),
            value: self.value,
            memo_type: self.memo.as_ref().map(|v| v.as_array()[0]).unwrap_or(0xf6),
            ovk: self.ovk,
        }
    }

    ///Take the fields plus additional inputs to send to builder
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

///Data needed for sapling transaction
#[derive(Debug)]
pub struct DataInput {
    ///transaction fee.
    /// Note: Ledger only supports fees of 10000 or 1000
    /// Note: Ledger only supports vectors up to length 5 at the moment for all below vectors
    pub txfee: u64,
    ///A vector of transparent inputs
    pub vec_tin: Vec<DataTransparentInput>,
    ///A vector of transparent outputs
    pub vec_tout: Vec<DataTransparentOutput>,
    ///A vector of shielded spends
    pub vec_sspend: Vec<DataShieldedSpend>,
    ///A vector of shielded outputs
    pub vec_soutput: Vec<DataShieldedOutput>,
}

impl DataInput {
    ///Prepares the data to send to the ledger
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

        InitData {
            t_in,
            t_out,
            s_spend,
            s_output,
        }
    }
}

//type PublicKeySapling = [u8; PK_LEN_SAPLING];

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

impl<E> ZcashApp<E>
where
    E: Exchange + Send + Sync,
    E::Error: std::error::Error,
    //this bound is unnecessary but it's repeated here
    // for the sake of documentation
    Self: AppExt<E>,
{
    /// Retrieve the app version
    pub async fn get_version(&self) -> Result<Version, LedgerAppError<E::Error>> {
        <Self as AppExt<E>>::get_version(&self.apdu_transport).await
    }

    /// Retrieve the app info
    pub async fn get_app_info(&self) -> Result<AppInfo, LedgerAppError<E::Error>> {
        <Self as AppExt<E>>::get_app_info(&self.apdu_transport).await
    }

    /// Retrieve the device info
    pub async fn get_device_info(&self) -> Result<DeviceInfo, LedgerAppError<E::Error>> {
        <Self as AppExt<E>>::get_device_info(&self.apdu_transport).await
    }

    ///Initiates a transaction in the ledger
    pub async fn init_tx(
        &self,
        data: InitData,
    ) -> Result<[u8; SHA256_DIGEST_SIZE], LedgerAppError<E::Error>> {
        let data = data.to_hsm_bytes();

        log::info!("sending inittx data to ledger");
        log::info!("{}", hex::encode(&data));

        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_INIT_TX,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: Vec::<u8>::new(),
        };

        let response =
            <Self as AppExt<E>>::send_chunks(&self.apdu_transport, start_command, &data).await?;

        log::info!("init ok");

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.is_empty() => {
                return Err(LedgerAppError::NoSignature)
            }
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let mut hash = [0u8; SHA256_DIGEST_SIZE];
        hash.copy_from_slice(&response_data[..SHA256_DIGEST_SIZE]);

        let mut sha256 = Sha256::new();
        sha256.update(data);
        let h = sha256.finalize();

        if h[..] != hash[..] {
            Err(LedgerAppError::AppSpecific(
                0,
                String::from("Something went wrong in data transport"),
            ))
        } else {
            Ok(hash)
        }
    }

    ///Initiates a transaction in the ledger
    pub async fn checkandsign(
        &self,
        data: HsmTxData,
    ) -> Result<[u8; 32], LedgerAppError<E::Error>> {
        //this is actually infallible
        let data = data.to_hsm_bytes().unwrap();

        let start_command = APDUCommand {
            cla: Self::CLA,
            ins: INS_CHECKANDSIGN,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: vec![],
        };

        let response =
            <Self as AppExt<E>>::send_chunks(&self.apdu_transport, start_command, &data).await?;
        log::info!("checkandsign ok");

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.is_empty() => {
                return Err(LedgerAppError::NoSignature)
            }
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let mut hash = [0u8; SHA256_DIGEST_SIZE];
        hash.copy_from_slice(&response_data[..SHA256_DIGEST_SIZE]);

        let mut sha256 = Sha256::new();
        sha256.update(data);
        let h = sha256.finalize();

        if h[..] != hash[..] {
            Err(LedgerAppError::AppSpecific(
                0,
                String::from("Something went wrong in data transport"),
            ))
        } else {
            Ok(hash)
        }
    }

    ///Does a complete transaction in the ledger
    pub async fn do_transaction<P: Parameters + Send + Sync>(
        &self,
        input: DataInput,
        parameters: P,
        branch: consensus::BranchId,
        target_height: u32,
    ) -> Result<(Transaction, SaplingMetadata), LedgerAppError<E::Error>> {
        log::info!("adding transaction data to builder");
        let fee = input.txfee;

        let builder: Builder = Builder::try_from(input)
            .map_err(|e: BuilderError| LedgerAppError::AppSpecific(0, e.to_string()))?;

        let prover = zcash_hsmbuilder::txprover::LocalTxProver::new(
            Path::new("../params/sapling-spend.params"),
            Path::new("../params/sapling-output.params"),
        );
        log::info!("building the transaction");

        // Set up a channel to recieve updates on the progress of building the transaction.
        let (tx, _) = std::sync::mpsc::channel();

        let txdata = builder
            .build(
                self,
                parameters,
                &prover,
                fee,
                &mut rand_core::OsRng,
                target_height,
                branch,
                Some(tx),
            )
            .await
            .map_err(|e| LedgerAppError::AppSpecific(0, e.to_string()))?;

        log::info!("transaction built and complete");
        Ok(txdata)
    }
}

impl<E> ZcashApp<E>
where
    E: Exchange,
    E::Error: std::error::Error,
{
    /// Retrieves an unshielded public key and address
    pub async fn get_address_unshielded(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<AddressUnshielded, LedgerAppError<E::Error>> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_GET_ADDR_SECP256K1,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();
        if response_data.len() < PK_LEN_SECP261K1 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut address = AddressUnshielded {
            public_key: [0; PK_LEN_SECP261K1],
            address: "".to_string(),
        };

        address
            .public_key
            .copy_from_slice(&response_data[..PK_LEN_SECP261K1]);
        address.address = str::from_utf8(&response_data[PK_LEN_SECP261K1..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .to_owned();

        Ok(address)
    }

    /// Retrieves a shielded public key and address
    pub async fn get_address_shielded(
        &self,
        path: u32,
        require_confirmation: bool,
    ) -> Result<AddressShielded, LedgerAppError<E::Error>> {
        let p1 = if require_confirmation { 1 } else { 0 };
        let mut path_data = Vec::with_capacity(4);
        path_data
            .write_u32::<LittleEndian>(path)
            .map_err(|_| LedgerAppError::AppSpecific(0, String::from("Invalid ZIP32-path")))?;

        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_GET_ADDR_SAPLING,
            p1,
            p2: 0x00,
            data: path_data,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();
        if response_data.len() < PK_LEN_SAPLING {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut bytes = [0u8; PK_LEN_SAPLING];
        bytes.copy_from_slice(&response_data[..PK_LEN_SAPLING]);

        let addr = PaymentAddress::from_bytes(&bytes).ok_or(LedgerAppError::Crypto)?;

        let mut address = AddressShielded {
            public_key: addr,
            address: "".to_string(),
        };

        address.address = str::from_utf8(&response_data[PK_LEN_SAPLING..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .to_owned();

        Ok(address)
    }

    ///Get list of diversifiers
    pub async fn get_div_list(
        &self,
        path: u32,
        index: &[u8; DIV_INDEX_SIZE],
    ) -> Result<[u8; DIV_LIST_SIZE], LedgerAppError<E::Error>> {
        let mut input_data = Vec::with_capacity(4);
        input_data
            .write_u32::<LittleEndian>(path)
            .map_err(|_| LedgerAppError::AppSpecific(0, String::from("Invalid ZIP32-path")))?;

        input_data.extend_from_slice(&index[..]);
        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_GET_DIV_LIST,
            p1: 0x00,
            p2: 0x00,
            data: input_data,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        // Last response should contain the answer
        if response_data.len() < DIV_LIST_SIZE {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("{}", hex::encode(response_data));

        let mut list = [0u8; DIV_LIST_SIZE];
        list.copy_from_slice(&response_data[..DIV_LIST_SIZE]);

        Ok(list)
    }

    /// Retrieves a shielded public key and address using a specific diversifier
    pub async fn get_address_shielded_with_div(
        &self,
        path: u32,
        div: &[u8; DIV_SIZE],
        require_confirmation: bool,
    ) -> Result<AddressShielded, LedgerAppError<E::Error>> {
        let p1 = if require_confirmation { 1 } else { 0 };
        let mut input_data = Vec::with_capacity(4);
        input_data
            .write_u32::<LittleEndian>(path)
            .map_err(|_| LedgerAppError::AppSpecific(0, String::from("Invalid ZIP32-path")))?;

        input_data.extend_from_slice(&div[..]);

        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_GET_ADDR_SAPLING_DIV,
            p1,
            p2: 0x00,
            data: input_data,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        // Last response should contain the answer
        if response_data.len() < PK_LEN_SAPLING {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("{}", hex::encode(response_data));

        let mut addrb = [0u8; PK_LEN_SAPLING];
        addrb.copy_from_slice(&response_data[..PK_LEN_SAPLING]);
        let addr = PaymentAddress::from_bytes(&addrb).ok_or(LedgerAppError::Crypto)?;

        let mut address = AddressShielded {
            public_key: addr,
            address: "".to_string(),
        };

        address.address = str::from_utf8(&response_data[PK_LEN_SAPLING..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .to_owned();

        Ok(address)
    }

    /// Retrieves a outgoing viewing key of a sapling key
    pub async fn get_ovk(&self, path: u32) -> Result<OutgoingViewingKey, LedgerAppError<E::Error>> {
        let mut input_data = Vec::with_capacity(4);
        input_data
            .write_u32::<LittleEndian>(path)
            .map_err(|_| LedgerAppError::AppSpecific(0, String::from("Invalid ZIP32-path")))?;

        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_GET_OVK,
            p1: 0x01,
            p2: 0x00,
            data: input_data,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        if response_data.len() < OVK_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut bytes = [0u8; OVK_SIZE];
        bytes.copy_from_slice(&response_data[0..OVK_SIZE]);

        let ovk = OutgoingViewingKey(bytes);

        Ok(ovk)
    }

    /// Retrieves a incoming viewing key of a sapling key
    pub async fn get_ivk(&self, path: u32) -> Result<jubjub::Fr, LedgerAppError<E::Error>> {
        let mut input_data = Vec::with_capacity(4);
        input_data
            .write_u32::<LittleEndian>(path)
            .map_err(|_| LedgerAppError::AppSpecific(0, String::from("Invalid ZIP32-path")))?;

        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_GET_IVK,
            p1: 0x01,
            p2: 0x00,
            data: input_data,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        if response_data.len() < IVK_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut bytes = [0u8; IVK_SIZE];
        bytes.copy_from_slice(&response_data[0..IVK_SIZE]);

        let y = jubjub::Fr::from_bytes(&bytes);
        if y.is_some().into() {
            Ok(y.unwrap())
        } else {
            Err(LedgerAppError::InvalidPK)
        }
    }

    ///Get the information needed from ledger to make a shielded spend
    pub async fn get_spendinfo(
        &self,
    ) -> Result<(ProofGenerationKey, jubjub::Fr, jubjub::Fr), LedgerAppError<E::Error>> {
        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_EXTRACT_SPEND,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();
        if response_data.len() < SPENDDATA_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let bytes = response_data;

        let mut akb = [0u8; AK_SIZE];
        akb.copy_from_slice(&bytes[0..AK_SIZE]);
        let mut nskb = [0u8; NSK_SIZE];
        nskb.copy_from_slice(&bytes[AK_SIZE..AK_SIZE + NSK_SIZE]);

        let ak = jubjub::SubgroupPoint::from_bytes(&akb);
        let nsk = jubjub::Fr::from_bytes(&nskb);
        if ak.is_none().into() || nsk.is_none().into() {
            return Err(LedgerAppError::AppSpecific(
                0,
                String::from("Invalid proofgeneration bytes"),
            ));
        }

        let proofkey = ProofGenerationKey {
            ak: ak.unwrap(),
            nsk: nsk.unwrap(),
        };

        let mut rcvb = [0u8; RCV_SIZE];
        rcvb.copy_from_slice(&bytes[AK_SIZE + NSK_SIZE..AK_SIZE + NSK_SIZE + RCV_SIZE]);

        let f = jubjub::Fr::from_bytes(&rcvb);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(
                0,
                String::from("Invalid rcv bytes"),
            ));
        }
        let rcv = f.unwrap();

        let mut alphab = [0u8; ALPHA_SIZE];
        alphab.copy_from_slice(&bytes[AK_SIZE + NSK_SIZE + RCV_SIZE..SPENDDATA_SIZE]);

        let f = jubjub::Fr::from_bytes(&alphab);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(
                0,
                String::from("Invalid rcv bytes"),
            ));
        }
        let alpha = f.unwrap();

        Ok((proofkey, rcv, alpha))
    }

    ///Get the information needed from ledger to make a shielded output
    pub async fn get_outputinfo(
        &self,
    ) -> Result<(jubjub::Fr, Rseed, Option<HashSeed>), LedgerAppError<E::Error>> {
        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_EXTRACT_OUTPUT,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        if response_data.len() < OUTPUTDATA_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let bytes = response_data;

        let mut rcvb = [0u8; RCV_SIZE];
        rcvb.copy_from_slice(&bytes[0..RCV_SIZE]);

        let f = jubjub::Fr::from_bytes(&rcvb);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(
                0,
                String::from("Invalid rcv bytes"),
            ));
        }
        let rcv = f.unwrap();

        let mut rseedb = [0u8; RSEED_SIZE];
        rseedb.copy_from_slice(&bytes[RCV_SIZE..RCV_SIZE + RSEED_SIZE]);

        let rseed = Rseed::AfterZip212(rseedb);
        let hashseed = match bytes.len() {
            OUTPUTDATA_HASHSEED_SIZE => {
                let mut seed = [0u8; HASHSEED_SIZE];
                seed.copy_from_slice(&bytes[RCV_SIZE + RSEED_SIZE..OUTPUTDATA_HASHSEED_SIZE]);
                Some(HashSeed(seed))
            }
            _ => None,
        };
        Ok((rcv, rseed, hashseed))
    }

    /// Get nullifier from note commitment and note position
    pub async fn get_nullifier(
        &self,
        path: u32,
        position: u64,
        note_commitment: &[u8; NOTE_COMMITMENT_SIZE],
    ) -> Result<Nullifier, LedgerAppError<E::Error>> {
        let mut input_data = Vec::with_capacity(4 + 8 + NOTE_COMMITMENT_SIZE);
        input_data.extend_from_slice(&path.to_le_bytes());
        input_data.extend_from_slice(&position.to_le_bytes());
        input_data.extend_from_slice(&note_commitment[..]);

        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_GET_NF,
            p1: 0x01,
            p2: 0x00,
            data: input_data,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        if response_data.len() < NF_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut nf_bytes = [0u8; NF_SIZE];
        nf_bytes.copy_from_slice(&response_data[0..NF_SIZE]);

        let nf = Nullifier(nf_bytes);

        Ok(nf)
    }

    ///Get a transparent signature from the ledger
    pub async fn get_transparent_signature(
        &self,
    ) -> Result<secp256k1::ecdsa::Signature, LedgerAppError<E::Error>> {
        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_EXTRACT_TRANSSIG,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        if response_data.len() < SIG_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        secp256k1::ecdsa::Signature::from_compact(&response_data[0..SIG_SIZE])
            .map_err(|_| LedgerAppError::InvalidSignature)
    }

    ///Get a shielded spend signature from the ledger
    pub async fn get_spend_signature(&self) -> Result<Signature, LedgerAppError<E::Error>> {
        let command = APDUCommand {
            cla: Self::CLA,
            ins: INS_EXTRACT_SPENDSIG,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };

        let response = self.apdu_transport.exchange(&command).await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => {
                return Err(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                ))
            }
        }

        let response_data = response.data();

        if response_data.len() < SIG_SIZE {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("Received response {}", response_data.len());

        Signature::read(&response_data[..SIG_SIZE]).map_err(|_| LedgerAppError::InvalidSignature)
    }
}
