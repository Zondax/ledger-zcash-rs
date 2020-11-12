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
type PublicKeySapling = [u8; PK_LEN_SAPLING];

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
    pub public_key: PublicKeySapling,
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

        let mut address = AddressShielded {
            public_key: [0; PK_LEN_SAPLING],
            address: "".to_string(),
        };

        address
            .public_key
            .copy_from_slice(&response.data[..PK_LEN_SAPLING]);
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
}