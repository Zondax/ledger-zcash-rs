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
    use ledger_zcash::{APDUTransport, ZcashApp, PK_LEN_SAPLING, PK_LEN_SECP261K1};
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

        let path = BIP44Path::from_string("m/44'/133'/1'/0/0").unwrap();
        let resp = app.get_address_shielded(&path, false).await.unwrap();

        assert_eq!(resp.public_key.to_bytes().len(), PK_LEN_SAPLING);

        let pkhex = hex::encode(&resp.public_key.to_bytes());
        println!("Public Key   {:?}", pkhex);
        println!("Address address {:?}", resp.address);

        assert_eq!(
            pkhex,
            "fa73b4c8ef0b7b49bb3c94bf2e1df1b27fbf73bb9599cf747714d1fa8b3bf2fb8fe600aca010f875b6ea53"
        );
        assert_eq!(
            resp.address,
            "zs1lfemfj80pda5nweujjlju803kflm7uamjkvu7arhzngl4zem7taclesq4jspp7r4km49xhd74ga"
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

        let path = BIP44Path::from_string("m/44'/133'/1'/0/0").unwrap();
        let resp = app.get_address_shielded(&path, true).await.unwrap();

        assert_eq!(resp.public_key.to_bytes().len(), PK_LEN_SAPLING);

        let pkhex = hex::encode(&resp.public_key.to_bytes());
        println!("Public Key   {:?}", pkhex);
        println!("Address address {:?}", resp.address);

        assert_eq!(
            pkhex,
            "fa73b4c8ef0b7b49bb3c94bf2e1df1b27fbf73bb9599cf747714d1fa8b3bf2fb8fe600aca010f875b6ea53"
        );
        assert_eq!(
            resp.address,
            "zs1lfemfj80pda5nweujjlju803kflm7uamjkvu7arhzngl4zem7taclesq4jspp7r4km49xhd74ga"
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
}
