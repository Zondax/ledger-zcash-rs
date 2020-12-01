/*******************************************************************************
*   (c) 2020 Zondax GmbH
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

use ledger_transport::{APDUCommand, APDUErrorCodes, APDUTransport};
use ledger_zondax_generic::{
    map_apdu_error_description, AppInfo, ChunkPayloadType, DeviceInfo, LedgerAppError, Version,
};
use std::path::Path;
use std::str;
use zx_bip44::BIP44Path;

extern crate hex;

use group::GroupEncoding;
use zcash_hsmbuilder::txbuilder_ledger::TransactionMetadata;
use zcash_hsmbuilder::{
    LedgerInitData, OutputBuilderInfo, ShieldedOutputData, ShieldedSpendData, SpendBuilderInfo,
    TinData, ToutData, TransactionSignatures, TransparentInputBuilderInfo,
    TransparentOutputBuilderInfo,
};
use zcash_primitives::keys::*;
use zcash_primitives::legacy::Script;
use zcash_primitives::merkle_tree::IncrementalWitness;
use zcash_primitives::note_encryption::Memo;
use zcash_primitives::primitives::Rseed;
use zcash_primitives::primitives::{PaymentAddress, ProofGenerationKey};
use zcash_primitives::redjubjub::Signature;
use zcash_primitives::sapling::Node;
use zcash_primitives::transaction::components::{Amount, OutPoint};
use zcash_primitives::transaction::Transaction;
//use zcash_primitives::transaction::Transaction;

///Data needed to handle transparent input for sapling transaction
///Contains information needed for both ledger and builder
pub struct LedgerDataTransparentInput {
    ///BIP44 path for transparent input key derivation
    pub path: BIP44Path,
    ///Public key belonging to the secret key (of the BIP44 path)
    pub pk: secp256k1::PublicKey,
    ///UTXO of transparent input
    pub prevout: OutPoint,
    ///Script of transparent input
    pub script: Script,
    ///Value of transparent input
    pub value: Amount,
}

impl LedgerDataTransparentInput {
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
pub struct LedgerDataTransparentOutput {
    ///The transparent output value
    pub value: Amount,
    ///The transparent output script
    pub script_pubkey: Script,
}

impl LedgerDataTransparentOutput {
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
pub struct LedgerDataShieldedSpend {
    ///ZIP32 path (last non-constant value)
    pub path: u32,
    ///Address of input spend note
    pub address: PaymentAddress,
    ///Value associated with note
    pub value: Amount,
    ///Witness for the spend note
    pub witness: IncrementalWitness<Node>,
    ///Used Rseed of the spend note (needed to compute nullifier)
    /// Note: only Rseed::AfterZip202 supported
    pub rseed: Rseed,
}

impl LedgerDataShieldedSpend {
    ///Take the fields needed to send to ledger
    pub fn to_init_data(&self) -> ShieldedSpendData {
        ShieldedSpendData {
            path: self.path,
            address: self.address.clone(),
            value: self.value,
        }
    }

    ///Take the fields plus additional inputs to send to builder
    pub fn to_builder_data(
        &self,
        spendinfo: (ProofGenerationKey, jubjub::Fr, jubjub::Fr),
    ) -> SpendBuilderInfo {
        SpendBuilderInfo {
            proofkey: spendinfo.0,
            rcv: spendinfo.1,
            alpha: spendinfo.2,
            address: self.address.clone(),
            value: self.value,
            witness: self.witness.clone(),
            rseed: self.rseed,
        }
    }
}

///Data needed to handle shielded output for sapling transaction
pub struct LedgerDataShieldedOutput {
    ///address of shielded output
    pub address: PaymentAddress,
    ///value send to that address
    pub value: Amount,
    ///Optional outgoing viewing key
    pub ovk: Option<OutgoingViewingKey>,
    ///Optional Memo
    pub memo: Option<Memo>,
}

impl LedgerDataShieldedOutput {
    ///Constructs the fields needed to send to ledger
    ///Ledger only checks memo-type, not the content
    pub fn to_init_data(&self) -> ShieldedOutputData {
        ShieldedOutputData {
            address: self.address.clone(),
            value: self.value,
            memotype: if self.memo.is_none() {
                0xf6
            } else {
                self.memo.clone().unwrap().as_bytes()[0]
            },
            ovk: self.ovk,
        }
    }

    ///Take the fields plus additional inputs to send to builder
    pub fn to_builder_data(&self, outputinfo: (jubjub::Fr, Rseed)) -> OutputBuilderInfo {
        OutputBuilderInfo {
            rcv: outputinfo.0,
            rseed: outputinfo.1,
            ovk: self.ovk,
            address: self.address.clone(),
            value: self.value,
            memo: self.memo.clone(),
        }
    }
}

///Data needed for sapling transaction
pub struct LedgerDataInput {
    ///transaction fee.
    /// Note: Ledger only supports fees of 10000 or 1000
    /// Note: Ledger only supports vectors up to length 5 at the moment for all below vectors
    pub txfee: u64,
    ///A vector of transparent inputs
    pub vec_tin: Vec<LedgerDataTransparentInput>,
    ///A vector of transparent outputs
    pub vec_tout: Vec<LedgerDataTransparentOutput>,
    ///A vector of shielded spends
    pub vec_sspend: Vec<LedgerDataShieldedSpend>,
    ///A vector of shielded outputs
    pub vec_soutput: Vec<LedgerDataShieldedOutput>,
}

impl LedgerDataInput {
    ///Prepares the data to send to the ledger
    pub fn to_inittx_data(&self) -> LedgerInitData {
        let mut t_in = Vec::with_capacity(self.vec_tin.len() * 54);
        for info in self.vec_tin.iter() {
            t_in.push(info.to_init_data());
        }

        let mut t_out = Vec::with_capacity(self.vec_tout.len() * 34);
        for info in self.vec_tout.iter() {
            t_out.push(info.to_init_data());
        }

        let mut s_spend = Vec::with_capacity(self.vec_sspend.len() * 55);
        for info in self.vec_sspend.iter() {
            s_spend.push(info.to_init_data());
        }

        let mut s_output = Vec::with_capacity(self.vec_soutput.len() * 55);
        for info in self.vec_soutput.iter() {
            s_output.push(info.to_init_data());
        }

        LedgerInitData {
            t_in,
            t_out,
            s_spend,
            s_output,
        }
    }
}

const INS_GET_IVK: u8 = 0xf0;
const INS_GET_OVK: u8 = 0xf4;
const INS_INIT_TX: u8 = 0xa0;
const INS_EXTRACT_SPEND: u8 = 0xa1;
const INS_EXTRACT_OUTPUT: u8 = 0xa2;
const INS_CHECKANDSIGN: u8 = 0xa3;
const INS_EXTRACT_SPENDSIG: u8 = 0xa4;
const INS_EXTRACT_TRANSSIG: u8 = 0xa5;
const INS_GET_DIV_LIST: u8 = 0x09;

const CLA: u8 = 0x85;
const INS_GET_ADDR_SECP256K1: u8 = 0x01;
const INS_SIGN_SECP256K1: u8 = 0x02;

const INS_GET_ADDR_SAPLING: u8 = 0x11;
const INS_GET_ADDR_SAPLING_DIV: u8 = 0x10;
//const INS_SIGN_SAPLING: u8 = 0x12;

/// Public Key Length (secp256k1)
pub const PK_LEN_SECP261K1: usize = 33;

/// Public Key Length (sapling)
pub const PK_LEN_SAPLING: usize = 43;

/// Ledger App
pub struct ZcashApp {
    apdu_transport: APDUTransport,
}

type PublicKeySecp256k1 = [u8; PK_LEN_SECP261K1];
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

type SignatureUnshielded = [u8; 65];

impl ZcashApp {
    /// Connect to the Ledger App
    pub fn new(apdu_transport: APDUTransport) -> Self {
        ZcashApp { apdu_transport }
    }

    fn cla(&self) -> u8 {
        CLA
    }

    /// Retrieve the app version
    pub async fn get_version(&self) -> Result<Version, LedgerAppError> {
        ledger_zondax_generic::get_version(self.cla(), &self.apdu_transport).await
    }

    /// Retrieve the app info
    pub async fn get_app_info(&self) -> Result<AppInfo, LedgerAppError> {
        ledger_zondax_generic::get_app_info(&self.apdu_transport).await
    }

    /// Retrieve the device info
    pub async fn get_device_info(&self) -> Result<DeviceInfo, LedgerAppError> {
        ledger_zondax_generic::get_device_info(&self.apdu_transport).await
    }

    /// Retrieves an unshielded public key and address
    pub async fn get_address_unshielded(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<AddressUnshielded, LedgerAppError> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_GET_ADDR_SECP256K1,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < PK_LEN_SECP261K1 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let mut address = AddressUnshielded {
            public_key: [0; PK_LEN_SECP261K1],
            address: "".to_string(),
        };

        address
            .public_key
            .copy_from_slice(&response.data[..PK_LEN_SECP261K1]);
        address.address = str::from_utf8(&response.data[PK_LEN_SECP261K1..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .to_owned();

        Ok(address)
    }

    /// Retrieves a shielded public key and address
    pub async fn get_address_shielded(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<AddressShielded, LedgerAppError> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_GET_ADDR_SAPLING,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < PK_LEN_SAPLING {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let mut bytes = [0u8; PK_LEN_SAPLING];
        bytes.copy_from_slice(&response.data[..PK_LEN_SAPLING]);

        let addr = PaymentAddress::from_bytes(&bytes);
        if addr.is_none() {
            return Err(LedgerAppError::Crypto);
        }

        let mut address = AddressShielded {
            public_key: addr.unwrap(),
            address: "".to_string(),
        };

        address.address = str::from_utf8(&response.data[PK_LEN_SAPLING..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .to_owned();

        Ok(address)
    }

    ///Get list of diversifiers
    pub async fn get_div_list(
        &self,
        path: &BIP44Path,
        index: &[u8; 11],
    ) -> Result<[u8; 220], LedgerAppError> {
        let serialized_path = path.serialize();
        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_GET_DIV_LIST,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: serialized_path,
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, index).await?;

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() < 220 {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("{}", hex::encode(&response.data[..]));

        let mut list = [0u8; 220];
        list.copy_from_slice(&response.data[..220]);

        Ok(list)
    }

    /// Retrieves a shielded public key and address using a specific diversifier
    pub async fn get_address_shielded_with_div(
        &self,
        path: &BIP44Path,
        div: &[u8; 11],
    ) -> Result<AddressShielded, LedgerAppError> {
        let serialized_path = path.serialize();
        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_GET_ADDR_SAPLING_DIV,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: serialized_path,
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, div).await?;

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() < 43 {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("{}", hex::encode(&response.data[..]));

        let mut addrb = [0u8; 43];
        addrb.copy_from_slice(&response.data[..43]);

        let addr = PaymentAddress::from_bytes(&addrb);

        if addr.is_none() {
            return Err(LedgerAppError::Crypto);
        }

        let mut address = AddressShielded {
            public_key: addr.unwrap(),
            address: "".to_string(),
        };

        address.address = str::from_utf8(&response.data[PK_LEN_SAPLING..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .to_owned();

        Ok(address)
    }

    /// Sign an unshielded transaction
    pub async fn sign_unshielded(
        &self,
        path: &BIP44Path,
        message: &[u8],
    ) -> Result<SignatureUnshielded, LedgerAppError> {
        let serialized_path = path.serialize();
        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_SIGN_SECP256K1,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: serialized_path,
        };

        log::info!("sign ->");
        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, message)
                .await?;
        log::info!("sign OK");

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() < 65 {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("{}", hex::encode(&response.data[..]));

        let mut sig: SignatureUnshielded = [0u8; 65];
        sig.copy_from_slice(&response.data[..65]);

        Ok(sig)
    }

    /// Retrieves a outgoing viewing key of a sapling key
    pub async fn get_ovk(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<OutgoingViewingKey, LedgerAppError> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_GET_OVK,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < 32 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&response.data[0..32]);

        let ovk = OutgoingViewingKey(bytes);

        Ok(ovk)
    }

    /// Retrieves a incoming viewing key of a sapling key
    pub async fn get_ivk(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<jubjub::Fr, LedgerAppError> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_GET_IVK,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < 32 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&response.data[0..32]);

        let f = jubjub::Fr::from_bytes(&bytes);

        if f.is_some().into() {
            Ok(f.unwrap())
        } else {
            Err(LedgerAppError::Crypto)
        }
    }

    ///Initiates a transaction in the ledger
    pub async fn init_tx(&self, data: &[u8]) -> Result<[u8; 32], LedgerAppError> {
        let dummy_path = BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap();
        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_INIT_TX,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: dummy_path.serialize(),
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, data).await?;
        log::info!("init ok");

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::NoSignature);
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&response.data[..32]);
        //check hash here?
        Ok(hash)
    }

    ///Get the information needed from ledger to make a shielded spend
    pub async fn get_spendinfo(
        &self,
    ) -> Result<(ProofGenerationKey, jubjub::Fr, jubjub::Fr), LedgerAppError> {
        let dummy_path = BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap();
        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_EXTRACT_SPEND,
            p1: 0x00,
            p2: 0x00,
            data: dummy_path.serialize(),
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < 64 + 32 + 32 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let bytes = response.data;

        let mut akb = [0u8; 32];
        akb.copy_from_slice(&bytes[0..32]);
        let mut nskb = [0u8; 32];
        nskb.copy_from_slice(&bytes[32..64]);

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

        let mut rcvb = [0u8; 32];
        rcvb.copy_from_slice(&bytes[64..96]);

        let f = jubjub::Fr::from_bytes(&rcvb);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(
                0,
                String::from("Invalid rcv bytes"),
            ));
        }
        let rcv = f.unwrap();

        let mut alphab = [0u8; 32];
        alphab.copy_from_slice(&bytes[96..128]);

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
    pub async fn get_outputinfo(&self) -> Result<(jubjub::Fr, Rseed), LedgerAppError> {
        let dummy_path = BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap();
        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_EXTRACT_OUTPUT,
            p1: 0x00,
            p2: 0x00,
            data: dummy_path.serialize(),
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < 64 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let bytes = response.data;

        let mut rcvb = [0u8; 32];
        rcvb.copy_from_slice(&bytes[0..32]);

        let f = jubjub::Fr::from_bytes(&rcvb);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(
                0,
                String::from("Invalid rcv bytes"),
            ));
        }
        let rcv = f.unwrap();

        let mut rseedb = [0u8; 32];
        rseedb.copy_from_slice(&bytes[32..64]);

        let rseed = Rseed::AfterZip212(rseedb);

        Ok((rcv, rseed))
    }

    ///Get a transparent signature from the ledger
    pub async fn get_transparent_signature(&self) -> Result<secp256k1::Signature, LedgerAppError> {
        let dummy_path = BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap();
        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_EXTRACT_TRANSSIG,
            p1: 0x00,
            p2: 0x00,
            data: dummy_path.serialize(),
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < 64 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let sig = secp256k1::Signature::from_compact(&response.data[0..64]);
        if sig.is_err() {
            Err(LedgerAppError::AppSpecific(
                1,
                String::from("invalid signature"),
            ))
        } else {
            Ok(sig.unwrap())
        }
    }

    ///Get a shielded spend signature from the ledger
    pub async fn get_spend_signature(&self) -> Result<Signature, LedgerAppError> {
        let dummy_path = BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap();
        let command = APDUCommand {
            cla: self.cla(),
            ins: INS_EXTRACT_SPENDSIG,
            p1: 0x00,
            p2: 0x00,
            data: dummy_path.serialize(),
        };

        let response = self.apdu_transport.exchange(&command).await?;
        if response.retcode != 0x9000 {
            return Err(LedgerAppError::AppSpecific(
                response.retcode,
                map_apdu_error_description(response.retcode).to_string(),
            ));
        }

        if response.data.len() < 64 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response.data.len());

        let sig = Signature::read(&response.data[..]);

        if sig.is_err() {
            Err(LedgerAppError::AppSpecific(
                1,
                String::from("invalid signature"),
            ))
        } else {
            Ok(sig.unwrap())
        }
    }

    ///Initiates a transaction in the ledger
    pub async fn checkandsign(&self, data: &[u8]) -> Result<[u8; 32], LedgerAppError> {
        let dummy_path = BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap();
        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_CHECKANDSIGN,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: dummy_path.serialize(),
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, data).await?;
        log::info!("checkandsign ok");

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::NoSignature);
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&response.data[..32]);
        //check hash here?
        Ok(hash)
    }

    ///Does a complete transaction in the ledger
    pub async fn do_transaction(
        &self,
        input: &LedgerDataInput,
    ) -> Result<(Transaction, TransactionMetadata), LedgerAppError> {
        let init_blob = input.to_inittx_data().to_ledger_bytes().unwrap();

        log::info!("sending inittx data to ledger");
        log::info!("{}", hex::encode(&init_blob));
        let r = self.init_tx(&init_blob).await;
        if r.is_err() {
            return Err(r.err().unwrap());
        }

        let mut builder = zcash_hsmbuilder::ZcashBuilderLedger::new(input.txfee);
        log::info!("adding transaction data to builder");
        for info in input.vec_tin.iter() {
            let r = builder.add_transparent_input(info.to_builder_data());
            if r.is_err() {
                return Err(LedgerAppError::Crypto);
            }
        }

        for info in input.vec_tout.iter() {
            let r = builder.add_transparent_output(info.to_builder_data());
            if r.is_err() {
                return Err(LedgerAppError::Crypto);
            }
        }

        for info in input.vec_sspend.iter() {
            log::info!("getting spend data from ledger");
            let req = self.get_spendinfo().await;
            if req.is_err() {
                return Err(LedgerAppError::Crypto);
            }
            let spendinfo = req.unwrap();
            let r = builder.add_sapling_spend(info.to_builder_data(spendinfo));
            if r.is_err() {
                return Err(LedgerAppError::Crypto);
            }
        }
        log::info!("getting output data from ledger");
        for info in input.vec_soutput.iter() {
            let req = self.get_outputinfo().await;
            if req.is_err() {
                return Err(LedgerAppError::Crypto);
            }
            let outputinfo = req.unwrap();
            let r = builder.add_sapling_output(info.to_builder_data(outputinfo));
            if r.is_err() {
                return Err(LedgerAppError::Crypto);
            }
        }
        let mut prover = zcash_hsmbuilder::txprover_ledger::LocalTxProverLedger::new(
            Path::new("../params/sapling-spend.params"),
            Path::new("../params/sapling-output.params"),
        );
        log::info!("building the transaction");
        let r = builder.build(&mut prover);
        if r.is_err() {
            return Err(LedgerAppError::AppSpecific(1, r.err().unwrap().to_string()));
        }
        log::info!("building the transaction success");
        let ledgertxblob = r.unwrap();
        log::info!("sending checkdata to ledger");
        let req = self.checkandsign(ledgertxblob.as_slice()).await;
        if req.is_err() {
            return Err(LedgerAppError::Crypto);
        }
        log::info!("checking and signing succeeded by ledger");

        let mut transparent_sigs = Vec::new();
        let mut spend_sigs = Vec::new();
        log::info!("requesting signatures");

        for _ in 0..input.vec_tin.len() {
            let req = self.get_transparent_signature().await;
            if req.is_err() {
                return Err(LedgerAppError::Crypto);
            }
            transparent_sigs.push(req.unwrap());
        }

        for _ in 0..input.vec_sspend.len() {
            let req = self.get_spend_signature().await;
            if req.is_err() {
                return Err(LedgerAppError::Crypto);
            }
            spend_sigs.push(req.unwrap());
        }
        log::info!("all signatures retrieved");
        let sigs = TransactionSignatures {
            transparent_sigs,
            spend_sigs,
        };
        log::info!("finalizing transaction");
        let r = builder.add_signatures(sigs);
        if r.is_err() {
            return Err(LedgerAppError::Crypto);
        }

        let r = builder.finalize();

        if r.is_err() {
            return Err(LedgerAppError::Crypto);
        }
        log::info!("final transaction complete");
        Ok(r.unwrap())
    }
}
