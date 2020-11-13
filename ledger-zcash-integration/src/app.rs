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
use std::str;
use zx_bip44::BIP44Path;

extern crate hex;

use zcash_primitives::keys::*;
use zcash_primitives::merkle_tree::IncrementalWitness;
use zcash_primitives::note_encryption::Memo;
use zcash_primitives::primitives::PaymentAddress;
use zcash_primitives::primitives::Rseed;
use zcash_primitives::sapling::Node;
use zcash_primitives::transaction::components::{Amount, TxIn, TxOut};
use zcashtools::{
    LedgerInitData, ShieldedOutputData, ShieldedSpendData, TinData, ToutData,
    TransparentInputBuilderInfo, TransparentOutputBuilderInfo,
};
//use zcash_primitives::transaction::Transaction;

///Data needed to handle transparent input for sapling transaction
///Contains information needed for both ledger and builder
pub struct LedgerDataTransparentInput {
    ///BIP44 path for transparent input key derivation
    pub path: BIP44Path,
    ///Public key belonging to the secret key (of the BIP44 path)
    pub pk: secp256k1::PublicKey,
    ///UTXO of transparent input
    pub txin: TxIn,
    ///Value of transparent input
    pub value: Amount,
}

impl LedgerDataTransparentInput {
    ///Takes the fields needed to send to the ledger
    pub fn to_init_data(&self) -> TinData {
        TinData {
            path: self.path.0.clone(),
            address: self.txin.script_sig.clone(),
            value: self.value.clone(),
        }
    }

    ///Takes the fields needed to send to the builder
    pub fn to_builder_data(&self) -> TransparentInputBuilderInfo {
        TransparentInputBuilderInfo {
            outp: self.txin.prevout.clone(),
            pk: self.pk,
            address: self.txin.script_sig.clone(),
            value: self.value.clone(),
        }
    }
}

///Data needed to handle transparent output for sapling transaction
pub struct LedgerDataTransparentOutput {
    ///The transparent output address and value
    pub txout: TxOut,
}

impl LedgerDataTransparentOutput {
    ///Decouples this struct to send to ledger
    pub fn to_init_data(&self) -> ToutData {
        ToutData {
            address: self.txout.script_pubkey.clone(),
            value: self.txout.value.clone(),
        }
    }
    ///Decouples this struct to send to builder
    pub fn to_builder_data(&self) -> TransparentOutputBuilderInfo {
        TransparentOutputBuilderInfo {
            address: self.txout.script_pubkey.clone(),
            value: self.txout.value.clone(),
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
            path: self.path.clone(),
            address: self.address.clone(),
            value: self.value.clone(),
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
            value: self.value.clone(),
            memotype: if self.memo.is_none() {
                0xf6
            } else {
                self.memo.clone().unwrap().as_bytes()[0]
            },
            ovk: self.ovk,
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

const CLA: u8 = 0x85;
const INS_GET_ADDR_SECP256K1: u8 = 0x01;
const INS_SIGN_SECP256K1: u8 = 0x02;

const INS_GET_ADDR_SAPLING: u8 = 0x11;
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
        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_INIT_TX,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: Vec::with_capacity(5 * 4),
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

    ///Does a complete transaction in the ledger
    pub async fn do_transaction(&self, input: LedgerDataInput) -> Result<(), LedgerAppError> {
        let init_blob = input.to_inittx_data().to_ledger_bytes().unwrap();

        let r = self.init_tx(&init_blob).await;
        if r.is_err() {
            return Err(r.err().unwrap());
        }

        //inittx
        //handletransparentinputs
        //handletransparentoutputs
        //handleshieldedspends
        //handleshieldedoutputs
        //checkandsign
        //handlesignatures
        //finalize
        Ok(())
    }
}
