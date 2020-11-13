/*******************************************************************************
*   (c) 2018-2020 Zondax GmbH
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
#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

extern crate hex;
#[macro_use]
extern crate matches;
#[macro_use]
extern crate serial_test;
extern crate ledger_zcash;

#[cfg(test)]
mod integration_tests {
    use env_logger::Env;
    use ledger_zcash::{APDUTransport, ZcashApp, PK_LEN_SAPLING, PK_LEN_SECP261K1, *};
    use zcash_primitives::keys::OutgoingViewingKey;
    use zcash_primitives::merkle_tree::IncrementalWitness;
    use zcash_primitives::primitives::PaymentAddress;
    use zcash_primitives::primitives::Rseed;
    use zcash_primitives::transaction::components::Amount;
    use zx_bip44::BIP44Path;

    fn init_logging() {
        let _ = env_logger::from_env(Env::default().default_filter_or("info"))
            .is_test(true)
            .try_init();
    }

    #[tokio::test]
    #[serial]
    async fn version() {
        init_logging();

        log::info!("Test");

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let resp = app.get_version().await.unwrap();

        println!("mode  {}", resp.mode);
        println!("major {}", resp.major);
        println!("minor {}", resp.minor);
        println!("patch {}", resp.patch);
        println!("locked {}", resp.locked);

        assert!(resp.major == 2);
    }

    #[tokio::test]
    #[serial]
    async fn address_unshielded() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let path = BIP44Path::from_string("m/44'/133'/0'/0/0").unwrap();
        let resp = app.get_address_unshielded(&path, false).await.unwrap();

        assert_eq!(resp.public_key.len(), PK_LEN_SECP261K1);

        let pkhex = hex::encode(&resp.public_key[..]);
        println!("Public Key   {:?}", pkhex);
        println!("Address address {:?}", resp.address);

        assert_eq!(
            pkhex,
            "0239511e41d70cf95ead40aae910cb3b6790f561f9077aaa1a8e091eeb78a8f26a"
        );
        assert_eq!(resp.address, "t1csLd5XeD1MyNM8gW8JfCzy8BYyidj6aCV");
    }

    #[tokio::test]
    #[serial]
    async fn address_shielded() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let path = BIP44Path::from_string("m/44'/133'/5'/0/1000").unwrap();
        let resp = app.get_address_shielded(&path, false).await.unwrap();

        assert_eq!(resp.public_key.to_bytes().len(), PK_LEN_SAPLING);

        let pkhex = hex::encode(&resp.public_key.to_bytes());
        println!("Public Key   {:?}", pkhex);
        println!("Address address {:?}", resp.address);

        assert_eq!(
            pkhex,
            "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667"
        );
        assert_eq!(
            resp.address,
            "zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3"
        );
    }

    #[tokio::test]
    #[serial]
    async fn show_address_unshielded() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let path = BIP44Path::from_string("m/44'/133'/0'/0/0").unwrap();
        let resp = app.get_address_unshielded(&path, true).await.unwrap();

        assert_eq!(resp.public_key.len(), PK_LEN_SECP261K1);

        let pkhex = hex::encode(&resp.public_key[..]);
        println!("Public Key   {:?}", pkhex);
        println!("Address address {:?}", resp.address);

        assert_eq!(
            pkhex,
            "0239511e41d70cf95ead40aae910cb3b6790f561f9077aaa1a8e091eeb78a8f26a"
        );
        assert_eq!(resp.address, "t1csLd5XeD1MyNM8gW8JfCzy8BYyidj6aCV");
    }

    #[tokio::test]
    #[serial]
    async fn show_address_shielded() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let path = BIP44Path::from_string("m/44'/133'/5'/0/1000").unwrap();
        let resp = app.get_address_shielded(&path, true).await.unwrap();

        assert_eq!(resp.public_key.to_bytes().len(), PK_LEN_SAPLING);

        let pkhex = hex::encode(&resp.public_key.to_bytes());
        println!("Public Key   {:?}", pkhex);
        println!("Address address {:?}", resp.address);

        assert_eq!(
            pkhex,
            "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667"
        );
        assert_eq!(
            resp.address,
            "zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3"
        );
    }

    #[tokio::test]
    #[serial]
    async fn sign_empty() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let path = BIP44Path::from_string("m/44'/133'/0'/0/5").unwrap();
        let some_message0 = b"";

        let response = app.sign_unshielded(&path, some_message0).await;
        assert!(response.is_err());
        assert!(matches!(
            response.err().unwrap(),
            ledger_zcash::LedgerAppError::InvalidEmptyMessage
        ));
    }

    #[tokio::test]
    async fn do_full_transaction_shieldedonly() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let spend1 = LedgerDataShieldedSpend {
            path: 1000,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            value: Amount::from_u64(75_000).unwrap(),
            witness: IncrementalWitness::read(
                &hex::decode(
                    "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                )
                .unwrap()[..],
            )
            .unwrap(),
            rseed: Rseed::AfterZip212([0u8; 32]),
        };

        let spend2 = LedgerDataShieldedSpend {
            path: 1000,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            value: Amount::from_u64(25_000).unwrap(),
            witness: IncrementalWitness::read(
                &hex::decode(
                    "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                )
                .unwrap()[..],
            )
            .unwrap(),
            rseed: Rseed::AfterZip212([0xFF; 32]),
        };

        let output1 = LedgerDataShieldedOutput {
            value: Amount::from_u64(80_000).unwrap(),
            address: PaymentAddress::from_bytes(&[
                21, 234, 231, 0, 224, 30, 36, 226, 19, 125, 85, 77, 103, 187, 13, 166, 78, 238, 11,
                241, 194, 195, 146, 197, 241, 23, 58, 151, 155, 174, 184, 153, 102, 56, 8, 205, 34,
                237, 141, 242, 117, 102, 204,
            ])
            .unwrap(),
            ovk: None,
            memo: None,
        };

        let txfee = Amount::from_u64(1000).unwrap();
        let change_amount = spend1.value + spend2.value - output1.value - txfee;

        let output2 = LedgerDataShieldedOutput {
            value: change_amount,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            ovk: Some(OutgoingViewingKey([
                111, 192, 30, 170, 102, 94, 3, 165, 60, 30, 3, 62, 208, 215, 123, 103, 12, 240,
                117, 237, 228, 173, 167, 105, 153, 122, 46, 210, 236, 34, 95, 202,
            ])),
            memo: None,
        };

        let input = LedgerDataInput {
            txfee: 1000,
            vec_tin: vec![],
            vec_tout: vec![],
            vec_sspend: vec![spend1, spend2],
            vec_soutput: vec![output1, output2],
        };

        let response = app.do_transaction(&input).await;
        assert!(response.is_ok());
    }
}
