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
extern crate ledger_zcash;
#[macro_use]
extern crate matches;
#[macro_use]
extern crate serial_test;

#[cfg(test)]
mod integration_tests {
    use std::path::Path;

    use env_logger::Env;
    use zcash_primitives::keys::OutgoingViewingKey;
    use zcash_primitives::legacy::Script;
    use zcash_primitives::merkle_tree::IncrementalWitness;
    use zcash_primitives::primitives::PaymentAddress;
    use zcash_primitives::primitives::Rseed;
    use zcash_primitives::transaction::components::{Amount, OutPoint};
    use zx_bip44::BIP44Path;

    use ledger_zcash::{APDUTransport, ZcashApp, PK_LEN_SAPLING, PK_LEN_SECP261K1, *};

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

        assert_eq!(resp.major, 2);
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
    async fn get_div_list() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let startindex: [u8; 11] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let path = BIP44Path::from_string("m/44'/133'/5'/0/1000").unwrap();

        let r = app.get_div_list(&path, &startindex).await;
        assert!(r.is_ok());
        let bytes = r.unwrap();
        assert_eq!(
            bytes[22..33],
            [198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220]
        );
    }

    #[tokio::test]
    async fn get_addr_with_div() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let div: [u8; 11] = [198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220];
        let path = BIP44Path::from_string("m/44'/133'/5'/0/1000").unwrap();

        let resp = app.get_address_shielded_with_div(&path, &div).await;
        assert!(resp.is_ok());
        let resp = resp.unwrap();
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
    async fn do_full_transaction_shieldedonly() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let spend1 = DataShieldedSpend {
            path: 1000,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            value: Amount::from_u64(50000).unwrap(),
            witness: IncrementalWitness::read(
                &hex::decode(
                    "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                )
                .unwrap()[..],
            )
            .unwrap(),
            rseed: Rseed::AfterZip212([0u8; 32]),
        };

        let spend2 = DataShieldedSpend {
            path: 1000,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            value: Amount::from_u64(50000).unwrap(),
            witness: IncrementalWitness::read(
                &hex::decode(
                    "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                )
                .unwrap()[..],
            )
            .unwrap(),
            rseed: Rseed::AfterZip212([0xFF; 32]),
        };

        let output1 = DataShieldedOutput {
            value: Amount::from_u64(60000).unwrap(),
            address: PaymentAddress::from_bytes(&[
                21, 234, 231, 0, 224, 30, 36, 226, 19, 125, 85, 77, 103, 187, 13, 166, 78, 238, 11,
                241, 194, 195, 146, 197, 241, 23, 58, 151, 155, 174, 184, 153, 102, 56, 8, 205, 34,
                237, 141, 242, 117, 102, 204,
            ])
            .unwrap(),
            ovk: None,
            memo: None,
        };

        let fee = 10000;

        let txfee = Amount::from_u64(fee).unwrap();
        let change_amount = spend1.value + spend2.value - output1.value - txfee;

        let output2 = DataShieldedOutput {
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

        let input = DataInput {
            txfee: fee,
            vec_tin: vec![],
            vec_tout: vec![],
            vec_sspend: vec![spend1, spend2],
            vec_soutput: vec![output1, output2],
        };

        let response = app.do_transaction(&input).await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn do_full_transaction_combinedshieldtransparent() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let tin1 = DataTransparentInput {
            path: BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap(),
            pk: secp256k1::PublicKey::from_slice(
                hex::decode("031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
            script: Script(
                hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap(),
            ),
            prevout: OutPoint::new([0u8; 32], 0),
            value: Amount::from_u64(60000).unwrap(),
        };

        let tout1 = DataTransparentOutput {
            value: Amount::from_u64(10000).unwrap(),
            script_pubkey: Script(
                hex::decode("76a914000000000000000000000000000000000000000088ac").unwrap(),
            ),
        };

        let spend1 = DataShieldedSpend {
            path: 1000,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            value: Amount::from_u64(50000).unwrap(),
            witness: IncrementalWitness::read(
                &hex::decode(
                    "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                )
                .unwrap()[..],
            )
            .unwrap(),
            rseed: Rseed::AfterZip212([0u8; 32]),
        };

        let output1 = DataShieldedOutput {
            value: Amount::from_u64(60000).unwrap(),
            address: PaymentAddress::from_bytes(&[
                21, 234, 231, 0, 224, 30, 36, 226, 19, 125, 85, 77, 103, 187, 13, 166, 78, 238, 11,
                241, 194, 195, 146, 197, 241, 23, 58, 151, 155, 174, 184, 153, 102, 56, 8, 205, 34,
                237, 141, 242, 117, 102, 204,
            ])
            .unwrap(),
            ovk: None,
            memo: None,
        };

        let fee = 1000;

        let txfee = Amount::from_u64(fee).unwrap();
        let change_amount = spend1.value + tin1.value - tout1.value - output1.value - txfee;

        let output2 = DataShieldedOutput {
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

        let input = DataInput {
            txfee: fee,
            vec_tin: vec![tin1],
            vec_tout: vec![tout1],
            vec_sspend: vec![spend1],
            vec_soutput: vec![output1, output2],
        };

        let r = app.do_transaction(&input).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn do_full_transaction_transparentonly() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let tin1 = DataTransparentInput {
            path: BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap(),
            pk: secp256k1::PublicKey::from_slice(
                hex::decode("031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
            script: Script(
                hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap(),
            ),
            prevout: OutPoint::new([0u8; 32], 0),
            value: Amount::from_u64(60000).unwrap(),
        };

        let tin2 = DataTransparentInput {
            path: BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap(),
            pk: secp256k1::PublicKey::from_slice(
                hex::decode("031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
            script: Script(
                hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap(),
            ),
            prevout: OutPoint::new([0u8; 32], 0),
            value: Amount::from_u64(40000).unwrap(),
        };

        let tout1 = DataTransparentOutput {
            value: Amount::from_u64(70000).unwrap(),
            script_pubkey: Script(
                hex::decode("76a914000000000000000000000000000000000000000088ac").unwrap(),
            ),
        };

        let fee = 1000;

        let txfee = Amount::from_u64(fee).unwrap();
        let change_amount = tin1.value + tin2.value - tout1.value - txfee;

        let tout2 = DataTransparentOutput {
            value: change_amount,
            script_pubkey: Script(
                hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap(),
            ),
        };

        let input = DataInput {
            txfee: fee,
            vec_tin: vec![tin1, tin2],
            vec_tout: vec![tout1, tout2],
            vec_sspend: vec![],
            vec_soutput: vec![],
        };

        let r = app.do_transaction(&input).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn do_full_tx_in_pieces() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = ZcashApp::new(transport);

        let spend1 = DataShieldedSpend {
            path: 1000,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            value: Amount::from_u64(50000).unwrap(),
            witness: IncrementalWitness::read(
                &hex::decode(
                    "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                )
                .unwrap()[..],
            )
            .unwrap(),
            rseed: Rseed::AfterZip212([0u8; 32]),
        };

        let spend2 = DataShieldedSpend {
            path: 1000,
            address: PaymentAddress::from_bytes(&[
                198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54,
                13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18,
                208, 102, 86, 114, 110, 162, 118, 103,
            ])
            .unwrap(),
            value: Amount::from_u64(50000).unwrap(),
            witness: IncrementalWitness::read(
                &hex::decode(
                    "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                )
                .unwrap()[..],
            )
            .unwrap(),
            rseed: Rseed::AfterZip212([0xFF; 32]),
        };

        let output1 = DataShieldedOutput {
            value: Amount::from_u64(60000).unwrap(),
            address: PaymentAddress::from_bytes(&[
                21, 234, 231, 0, 224, 30, 36, 226, 19, 125, 85, 77, 103, 187, 13, 166, 78, 238, 11,
                241, 194, 195, 146, 197, 241, 23, 58, 151, 155, 174, 184, 153, 102, 56, 8, 205, 34,
                237, 141, 242, 117, 102, 204,
            ])
            .unwrap(),
            ovk: None,
            memo: None,
        };

        let fee = 10000;

        let txfee = Amount::from_u64(fee).unwrap();
        let change_amount = spend1.value + spend2.value - output1.value - txfee;

        let output2 = DataShieldedOutput {
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

        let input = DataInput {
            txfee: fee,
            vec_tin: vec![],
            vec_tout: vec![],
            vec_sspend: vec![spend1, spend2],
            vec_soutput: vec![output1, output2],
        };

        let init_blob = input.to_inittx_data().to_hsm_bytes().unwrap();

        log::info!("sending inittx data to ledger");
        log::info!("{}", hex::encode(&init_blob));
        let r = app.init_tx(&init_blob).await;

        assert!(r.is_ok());

        let mut builder = zcash_hsmbuilder::ZcashBuilder::new(input.txfee);
        log::info!("adding transaction data to builder");
        for info in input.vec_tin.iter() {
            let r = builder.add_transparent_input(info.to_builder_data());
            assert!(r.is_ok());
        }

        for info in input.vec_tout.iter() {
            let r = builder.add_transparent_output(info.to_builder_data());
            assert!(r.is_ok());
        }

        for info in input.vec_sspend.iter() {
            log::info!("getting spend data from ledger");
            let req = app.get_spendinfo().await;
            assert!(req.is_ok());
            let spendinfo = req.unwrap();
            let r = builder.add_sapling_spend(info.to_builder_data(spendinfo));
            assert!(r.is_ok());
        }
        log::info!("getting output data from ledger");
        for info in input.vec_soutput.iter() {
            let req = app.get_outputinfo().await;
            let outputinfo = req.unwrap();
            let r = builder.add_sapling_output(info.to_builder_data(outputinfo));
            assert!(r.is_ok());
        }
        let mut prover = zcash_hsmbuilder::txprover::LocalTxProver::new(
            Path::new("../params/sapling-spend.params"),
            Path::new("../params/sapling-output.params"),
        );
        log::info!("building the transaction");
        let r = builder.build(&mut prover);
        assert!(r.is_ok());
        log::info!("building the transaction success");
        let ledgertxblob = r.unwrap();
        log::info!("sending checkdata to ledger");
        let req = app.checkandsign(ledgertxblob.as_slice()).await;
        assert!(req.is_ok());
        log::info!("checking and signing succeeded by ledger");

        let mut transparent_sigs = Vec::new();
        let mut spend_sigs = Vec::new();
        log::info!("requesting signatures");

        for _ in 0..input.vec_tin.len() {
            let req = app.get_transparent_signature().await;
            assert!(req.is_ok());
            transparent_sigs.push(req.unwrap());
        }

        for _ in 0..input.vec_sspend.len() {
            let req = app.get_spend_signature().await;
            assert!(req.is_ok());
            spend_sigs.push(req.unwrap());
        }
        log::info!("all signatures retrieved");
    }
}
