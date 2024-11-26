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

use std::str;

use byteorder::{LittleEndian, WriteBytesExt};
use group::GroupEncoding;
use ledger_transport::{APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{App, AppExt, AppInfo, ChunkPayloadType, DeviceInfo, LedgerAppError, Version};
use sha2::{Digest, Sha256};
use zx_bip44::BIP44Path;

use crate::config::*;

type PublicKeySecp256k1 = [u8; PK_LEN_SECP261K1];
type PaymentAddressRaw = [u8; PK_LEN_SAPLING];

type OutgoingViewKeyRaw = [u8; OVK_SIZE];

type RSeedRawAfterZip212 = [u8; RSEED_SIZE];

type NullifierRaw = [u8; NF_SIZE];

type SignatureRaw = [u8; SIG_SIZE];

/// -
type HashSeedRaw = [u8; HASHSEED_SIZE];

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
    pub public_key: PaymentAddressRaw,
    /// Address (exposed as SS58)
    pub address: String,
}

impl<E> ZcashApp<E>
where
    E: Exchange + Send + Sync,
    E::Error: std::error::Error,
    // this bound is unnecessary but it's repeated here
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

    /// Initiates a transaction in the ledger
    pub async fn init_tx(
        &self,
        data: Vec<u8>,
    ) -> Result<[u8; SHA256_DIGEST_SIZE], LedgerAppError<E::Error>> {
        log::info!("sending inittx data to ledger");
        log::info!("{}", hex::encode(&data));

        let start_command = APDUCommand {
            cla: self.cla(),
            ins: INS_INIT_TX,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: Vec::<u8>::new(),
        };

        let response = <Self as AppExt<E>>::send_chunks(&self.apdu_transport, start_command, &data).await?;

        log::info!("init ok");

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.is_empty() => return Err(LedgerAppError::NoSignature),
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let mut hash = [0u8; SHA256_DIGEST_SIZE];
        hash.copy_from_slice(&response_data[.. SHA256_DIGEST_SIZE]);

        let mut sha256 = Sha256::new();
        sha256.update(data);
        let h = sha256.finalize();

        if h[..] != hash[..] {
            Err(LedgerAppError::AppSpecific(0, String::from("Something went wrong in data transport")))
        } else {
            Ok(hash)
        }
    }

    /// Initiates a transaction in the ledger
    pub async fn checkandsign(
        &self,
        data: Vec<u8>,
        hex_tx_version: u8,
    ) -> Result<[u8; 32], LedgerAppError<E::Error>> {
        if hex_tx_version == 0u8 {
            return Err(LedgerAppError::AppSpecific(0, String::from("Unsupported transaction version")));
        }
        let start_command = APDUCommand {
            cla: Self::CLA,
            ins: INS_CHECKANDSIGN,
            p1: ChunkPayloadType::Init as u8,
            p2: hex_tx_version,
            data: vec![],
        };

        log::info!("checkandsign APDUCommand {:#?}", start_command);
        log::info!("hex_tx_version  {:#?}", hex_tx_version);

        let response = Self::send_chunks_p2_all(&self.apdu_transport, start_command, &data).await?;
        log::info!("checkandsign ok");

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.is_empty() => return Err(LedgerAppError::NoSignature),
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let mut hash = [0u8; SHA256_DIGEST_SIZE];
        hash.copy_from_slice(&response_data[.. SHA256_DIGEST_SIZE]);

        let mut sha256 = Sha256::new();
        sha256.update(data);
        let h = sha256.finalize();

        if h[..] != hash[..] {
            Err(LedgerAppError::AppSpecific(0, String::from("Something went wrong in data transport")))
        } else {
            Ok(hash)
        }
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

        let command = APDUCommand { cla: Self::CLA, ins: INS_GET_ADDR_SECP256K1, p1, p2: 0x00, data: serialized_path };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();
        if response_data.len() < PK_LEN_SECP261K1 {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut address = AddressUnshielded { public_key: [0; PK_LEN_SECP261K1], address: "".to_string() };

        address
            .public_key
            .copy_from_slice(&response_data[.. PK_LEN_SECP261K1]);
        str::from_utf8(&response_data[PK_LEN_SECP261K1 ..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .clone_into(&mut address.address);

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

        let command = APDUCommand { cla: Self::CLA, ins: INS_GET_ADDR_SAPLING, p1, p2: 0x00, data: path_data };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();
        if response_data.len() < PK_LEN_SAPLING {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut bytes = [0u8; PK_LEN_SAPLING];
        bytes.copy_from_slice(&response_data[.. PK_LEN_SAPLING]);

        let mut address = AddressShielded { public_key: bytes, address: "".to_string() };

        str::from_utf8(&response_data[PK_LEN_SAPLING ..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .clone_into(&mut address.address);

        Ok(address)
    }

    /// Get list of diversifiers
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
        let command = APDUCommand { cla: Self::CLA, ins: INS_GET_DIV_LIST, p1: 0x00, p2: 0x00, data: input_data };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        // Last response should contain the answer
        if response_data.len() < DIV_LIST_SIZE {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("{}", hex::encode(response_data));

        let mut list = [0u8; DIV_LIST_SIZE];
        list.copy_from_slice(&response_data[.. DIV_LIST_SIZE]);

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

        let command = APDUCommand { cla: Self::CLA, ins: INS_GET_ADDR_SAPLING_DIV, p1, p2: 0x00, data: input_data };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        // Last response should contain the answer
        if response_data.len() < PK_LEN_SAPLING {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("{}", hex::encode(response_data));

        let mut addrb = [0u8; PK_LEN_SAPLING];
        addrb.copy_from_slice(&response_data[.. PK_LEN_SAPLING]);

        let mut address = AddressShielded { public_key: addrb, address: "".to_string() };

        str::from_utf8(&response_data[PK_LEN_SAPLING ..])
            .map_err(|_e| LedgerAppError::Utf8)?
            .clone_into(&mut address.address);

        Ok(address)
    }

    /// Retrieves a outgoing viewing key of a sapling key
    pub async fn get_ovk(
        &self,
        path: u32,
    ) -> Result<OutgoingViewKeyRaw, LedgerAppError<E::Error>> {
        let mut input_data = Vec::with_capacity(4);
        input_data
            .write_u32::<LittleEndian>(path)
            .map_err(|_| LedgerAppError::AppSpecific(0, String::from("Invalid ZIP32-path")))?;

        let command = APDUCommand { cla: Self::CLA, ins: INS_GET_OVK, p1: 0x01, p2: 0x00, data: input_data };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        if response_data.len() < OVK_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut ovk_raw = [0u8; OVK_SIZE];
        ovk_raw.copy_from_slice(&response_data[0 .. OVK_SIZE]);

        Ok(ovk_raw)
    }

    /// Retrieves a incoming viewing key of a sapling key
    pub async fn get_ivk(
        &self,
        path: u32,
    ) -> Result<jubjub::Fr, LedgerAppError<E::Error>> {
        let mut input_data = Vec::with_capacity(4);
        input_data
            .write_u32::<LittleEndian>(path)
            .map_err(|_| LedgerAppError::AppSpecific(0, String::from("Invalid ZIP32-path")))?;

        let command = APDUCommand { cla: Self::CLA, ins: INS_GET_IVK, p1: 0x01, p2: 0x00, data: input_data };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        if response_data.len() < IVK_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut bytes = [0u8; IVK_SIZE];
        bytes.copy_from_slice(&response_data[0 .. IVK_SIZE]);

        let y = jubjub::Fr::from_bytes(&bytes);
        if y.is_some().into() {
            Ok(y.unwrap())
        } else {
            Err(LedgerAppError::InvalidPK)
        }
    }

    /// Get the information needed from ledger to make a shielded spend
    pub async fn get_spendinfo(
        &self
    ) -> Result<(jubjub::SubgroupPoint, jubjub::Fr, jubjub::Fr, jubjub::Fr), LedgerAppError<E::Error>> {
        let command = APDUCommand { cla: Self::CLA, ins: INS_EXTRACT_SPEND, p1: 0x00, p2: 0x00, data: vec![] };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();
        if response_data.len() < SPENDDATA_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let bytes = response_data;

        let mut akb = [0u8; AK_SIZE];
        akb.copy_from_slice(&bytes[0 .. AK_SIZE]);
        let mut nskb = [0u8; NSK_SIZE];
        nskb.copy_from_slice(&bytes[AK_SIZE .. AK_SIZE + NSK_SIZE]);

        let ak = jubjub::SubgroupPoint::from_bytes(&akb);
        let nsk = jubjub::Fr::from_bytes(&nskb);
        if ak.is_none().into() || nsk.is_none().into() {
            return Err(LedgerAppError::AppSpecific(0, String::from("Invalid proofgeneration bytes")));
        }

        let ak = ak.unwrap();
        let nsk = nsk.unwrap();

        let mut rcvb = [0u8; RCV_SIZE];
        rcvb.copy_from_slice(&bytes[AK_SIZE + NSK_SIZE .. AK_SIZE + NSK_SIZE + RCV_SIZE]);

        let f = jubjub::Fr::from_bytes(&rcvb);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(0, String::from("Invalid rcv bytes")));
        }
        let rcv = f.unwrap();

        let mut alphab = [0u8; ALPHA_SIZE];
        alphab.copy_from_slice(&bytes[AK_SIZE + NSK_SIZE + RCV_SIZE .. SPENDDATA_SIZE]);

        let f = jubjub::Fr::from_bytes(&alphab);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(0, String::from("Invalid rcv bytes")));
        }
        let alpha = f.unwrap();

        Ok((ak, nsk, rcv, alpha))
    }

    /// Get the information needed from ledger to make a shielded output
    pub async fn get_outputinfo(
        &self
    ) -> Result<(jubjub::Fr, RSeedRawAfterZip212, Option<HashSeedRaw>), LedgerAppError<E::Error>> {
        let command = APDUCommand { cla: Self::CLA, ins: INS_EXTRACT_OUTPUT, p1: 0x00, p2: 0x00, data: vec![] };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        if response_data.len() < OUTPUTDATA_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let bytes = response_data;

        let mut rcvb = [0u8; RCV_SIZE];
        rcvb.copy_from_slice(&bytes[0 .. RCV_SIZE]);

        let f = jubjub::Fr::from_bytes(&rcvb);
        if f.is_none().into() {
            return Err(LedgerAppError::AppSpecific(0, String::from("Invalid rcv bytes")));
        }
        let rcv = f.unwrap();

        let mut rseedb_afterzip212 = [0u8; RSEED_SIZE];
        rseedb_afterzip212.copy_from_slice(&bytes[RCV_SIZE .. RCV_SIZE + RSEED_SIZE]);

        let outputdata_hashseed_size = RCV_SIZE + RSEED_SIZE + HASHSEED_SIZE;

        let hashseed = if bytes.len() == outputdata_hashseed_size {
            let mut seed = [0u8; HASHSEED_SIZE];
            seed.copy_from_slice(&bytes[RCV_SIZE + RSEED_SIZE .. outputdata_hashseed_size]);
            Some(seed)
        } else {
            None
        };

        Ok((rcv, rseedb_afterzip212, hashseed))
    }

    /// Get nullifier from note commitment and note position
    pub async fn get_nullifier(
        &self,
        path: u32,
        position: u64,
        note_commitment: &[u8; NOTE_COMMITMENT_SIZE],
    ) -> Result<NullifierRaw, LedgerAppError<E::Error>> {
        let mut input_data = Vec::with_capacity(4 + 8 + NOTE_COMMITMENT_SIZE);
        input_data.extend_from_slice(&path.to_le_bytes());
        input_data.extend_from_slice(&position.to_le_bytes());
        input_data.extend_from_slice(&note_commitment[..]);

        let command = APDUCommand { cla: Self::CLA, ins: INS_GET_NF, p1: 0x01, p2: 0x00, data: input_data };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        if response_data.len() < NF_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        let mut nf_bytes = [0u8; NF_SIZE];
        nf_bytes.copy_from_slice(&response_data[0 .. NF_SIZE]);

        Ok(nf_bytes)
    }

    /// Get a transparent signature from the ledger
    pub async fn get_transparent_signature(&self) -> Result<secp256k1::ecdsa::Signature, LedgerAppError<E::Error>> {
        let command = APDUCommand { cla: Self::CLA, ins: INS_EXTRACT_TRANSSIG, p1: 0x00, p2: 0x00, data: vec![] };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        if response_data.len() < SIG_SIZE {
            return Err(LedgerAppError::InvalidPK);
        }

        log::info!("Received response {}", response_data.len());

        secp256k1::ecdsa::Signature::from_compact(&response_data[0 .. SIG_SIZE])
            .map_err(|_| LedgerAppError::InvalidSignature)
    }

    /// Get a shielded spend signature from the ledger
    pub async fn get_spend_signature(&self) -> Result<SignatureRaw, LedgerAppError<E::Error>> {
        let command = APDUCommand { cla: Self::CLA, ins: INS_EXTRACT_SPENDSIG, p1: 0x00, p2: 0x00, data: vec![] };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await?;
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => {},
            Ok(err) => return Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => return Err(LedgerAppError::AppSpecific(err, "[APDU_ERROR] Unknown".to_string())),
        }

        let response_data = response.data();

        if response_data.len() < SIG_SIZE {
            return Err(LedgerAppError::InvalidSignature);
        }

        log::info!("Received response {}", response_data.len());

        let mut signature_raw = [0u8; SIG_SIZE];
        signature_raw.copy_from_slice(&response_data[0 .. SIG_SIZE]);

        Ok(signature_raw)
    }
}
