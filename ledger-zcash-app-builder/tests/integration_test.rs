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
use env_logger::Env;
use serial_test::serial;
use zx_bip44::BIP44Path;

#[path = "../src/zcash.rs"]
mod zcash;

use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
use ledger_zcash_app_builder::config::{PK_LEN_SAPLING, PK_LEN_SECP261K1};
use ledger_zcash_app_builder::*;
use zcash_primitives::{
    consensus::{self, TestNetwork},
    keys::OutgoingViewingKey,
    legacy::Script,
    merkle_tree::IncrementalWitness,
    sapling::{Note, PaymentAddress, Rseed},
    transaction::components::{Amount, OutPoint},
};

lazy_static::lazy_static! {
    static ref HIDAPI: HidApi = HidApi::new().expect("Failed to create Hidapi");
}

fn init_logging() {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .is_test(true)
        .try_init();
}

#[tokio::test]
#[serial]
async fn version() {
    init_logging();

    log::info!("Test");

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let resp = app.app.get_version().await.unwrap();

    println!("mode  {}", resp.mode);
    println!("major {}", resp.major);
    println!("minor {}", resp.minor);
    println!("patch {}", resp.patch);
    println!("locked {}", resp.locked);

    assert_eq!(resp.major, 3);
}

#[tokio::test]
#[serial]
async fn get_key_ivk() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let path = 1000;

    let resp = app.app.get_ivk(path).await.unwrap();

    let ivk = hex::encode(resp.to_bytes());

    assert_eq!(ivk, "6dfadf175921e6fbfa093c8f7c704a0bdb07328474f56c833dfcfa5301082d03");
}

#[tokio::test]
#[serial]
async fn get_key_ovk() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let path = 1000;

    let resp = app.app.get_ovk(path).await.unwrap();

    let ovk = hex::encode(resp);

    assert_eq!(ovk, "6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca");
}

#[tokio::test]
#[serial]
async fn get_nf() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let path = 1000;

    let pos: u64 = 2578461368;

    let cm: [u8; 32] = [
        33, 201, 70, 152, 202, 50, 75, 76, 186, 206, 41, 29, 39, 171, 182, 138, 10, 175, 39, 55, 220, 69, 86, 84, 28,
        127, 205, 232, 206, 17, 221, 232,
    ];

    let resp = app
        .app
        .get_nullifier(path, pos, &cm)
        .await
        .unwrap();
    let vec_nf = resp.to_vec();
    let expected_nf: Vec<u8> = [
        37, 241, 242, 207, 94, 44, 43, 195, 29, 7, 182, 111, 77, 84, 240, 144, 173, 137, 177, 152, 137, 63, 18, 173,
        174, 68, 125, 223, 132, 226, 20, 90,
    ]
    .to_vec();
    assert_eq!(vec_nf, expected_nf);
}

#[tokio::test]
#[serial]
async fn address_unshielded() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let path = BIP44Path::from_string("m/44'/133'/0'/0/0").unwrap();
    let resp = app
        .app
        .get_address_unshielded(&path, false)
        .await
        .unwrap();

    assert_eq!(resp.public_key.len(), PK_LEN_SECP261K1);

    let pk_hex = hex::encode(&resp.public_key[..]);
    println!("Public Key   {:?}", pk_hex);
    println!("Address address {:?}", resp.address);

    assert_eq!(pk_hex, "0239511e41d70cf95ead40aae910cb3b6790f561f9077aaa1a8e091eeb78a8f26a");
    assert_eq!(resp.address, "t1csLd5XeD1MyNM8gW8JfCzy8BYyidj6aCV");
}

#[tokio::test]
#[serial]
async fn address_shielded() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let path = 1000;
    let resp = app
        .app
        .get_address_shielded(path, false)
        .await
        .unwrap();

    assert_eq!(resp.public_key.len(), PK_LEN_SAPLING);

    let pk_hex = hex::encode(resp.public_key);
    println!("Public Key   {:?}", pk_hex);
    println!("Address address {:?}", resp.address);

    assert_eq!(pk_hex, "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667");
    assert_eq!(resp.address, "zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3");
}

#[tokio::test]
#[serial]
async fn show_address_unshielded() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let path = BIP44Path::from_string("m/44'/133'/0'/0/0").unwrap();
    let resp = app
        .app
        .get_address_unshielded(&path, true)
        .await
        .unwrap();

    assert_eq!(resp.public_key.len(), PK_LEN_SECP261K1);

    let pk_hex = hex::encode(&resp.public_key[..]);
    println!("Public Key   {:?}", pk_hex);
    println!("Address address {:?}", resp.address);

    assert_eq!(pk_hex, "0239511e41d70cf95ead40aae910cb3b6790f561f9077aaa1a8e091eeb78a8f26a");
    assert_eq!(resp.address, "t1csLd5XeD1MyNM8gW8JfCzy8BYyidj6aCV");
}

#[tokio::test]
#[serial]
async fn show_address_shielded() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let path = 1000;
    let resp = app
        .app
        .get_address_shielded(path, true)
        .await
        .unwrap();

    assert_eq!(resp.public_key.len(), PK_LEN_SAPLING);

    let pk_hex = hex::encode(resp.public_key);
    println!("Public Key   {:?}", pk_hex);
    println!("Address address {:?}", resp.address);

    assert_eq!(pk_hex, "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667");
    assert_eq!(resp.address, "zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3");
}

#[tokio::test]
#[serial]
async fn get_div_list() {
    init_logging();
    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let startindex: [u8; 11] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let path = 1000;

    let r = app
        .app
        .get_div_list(path, &startindex)
        .await;
    assert!(r.is_ok());
    let bytes = r.unwrap();
    assert_eq!(bytes[22 .. 33], [198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220]);
}

#[tokio::test]
#[serial]
async fn get_addr_with_div() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let div: [u8; 11] = [198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220];
    let path = 1000;

    let resp = app
        .app
        .get_address_shielded_with_div(path, &div, true)
        .await;
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let pk_hex = hex::encode(resp.public_key);
    println!("Public Key   {:?}", pk_hex);
    println!("Address address {:?}", resp.address);

    assert_eq!(pk_hex, "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667");
    assert_eq!(resp.address, "zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3");
}

#[tokio::test]
#[serial]
async fn do_full_transaction_shieldedonly() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let addr = PaymentAddress::from_bytes(&[
        198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54, 13, 249, 93, 202, 223, 140,
        15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18, 208, 102, 86, 114, 110, 162, 118, 103,
    ])
    .unwrap();

    let d = addr.diversifier();

    let spend1 = DataShieldedSpend {
        path: 1000,
        diversifier: *d,
        note: Note {
            value: 50000,
            rseed: Rseed::AfterZip212([0u8; 32]),
            g_d: d.g_d().unwrap(),
            pk_d: *addr.pk_d(),
        },
        witness: IncrementalWitness::read(
            &hex::decode(
                "0102cda01d86b1a443f4012e639556616fa4638233b93a61d12bd30c38ca678d69000101fef93fadf0bfbd769ec217949b45ca5fef3f1b6ae2aebdfbfac8a5f29cd9e24901d0282378d8c5c23edd6be1a5ab023ab608c3ba21411dd7824dd1f52ad074382a00",
            )
            .unwrap()[..],
        )
        .unwrap()
        .path()
        .unwrap(),
    };

    let spend1_ = spend1.clone();
    let spend2 = DataShieldedSpend {
        note: Note {
            rseed: Rseed::AfterZip212([0xFF; 32]),
            ..spend1_.note
        },
        witness: IncrementalWitness::read(
            &hex::decode(
                "0102cda01d86b1a443f4012e639556616fa4638233b93a61d12bd30c38ca678d6901d0282378d8c5c23edd6be1a5ab023ab608c3ba21411dd7824dd1f52ad074382a0101fef93fadf0bfbd769ec217949b45ca5fef3f1b6ae2aebdfbfac8a5f29cd9e2490000"
            ).unwrap()[..])
            .unwrap().path().unwrap(),
        ..spend1_
    };

    let output1 = DataShieldedOutput {
        value: Amount::from_u64(60000).unwrap(),
        address: PaymentAddress::from_bytes(&[
            21, 234, 231, 0, 224, 30, 36, 226, 19, 125, 85, 77, 103, 187, 13, 166, 78, 238, 11, 241, 194, 195, 146,
            197, 241, 23, 58, 151, 155, 174, 184, 153, 102, 56, 8, 205, 34, 237, 141, 242, 117, 102, 204,
        ])
        .unwrap(),
        ovk: None,
        memo: None,
    };

    let fee = 1000;

    let change_amount = spend1.note.value + spend2.note.value - u64::from(output1.value) - fee;

    let output2 = DataShieldedOutput {
        value: Amount::from_u64(change_amount).unwrap(),
        address: PaymentAddress::from_bytes(&[
            198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54, 13, 249, 93, 202, 223,
            140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18, 208, 102, 86, 114, 110, 162, 118, 103,
        ])
        .unwrap(),
        ovk: Some(OutgoingViewingKey([
            111, 192, 30, 170, 102, 94, 3, 165, 60, 30, 3, 62, 208, 215, 123, 103, 12, 240, 117, 237, 228, 173, 167,
            105, 153, 122, 46, 210, 236, 34, 95, 202,
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

    let response = app
        .do_transaction(input, TestNetwork, consensus::BranchId::Sapling, None, 0)
        .await;
    assert!(response.is_ok());
}

#[tokio::test]
#[serial]
async fn do_full_transaction_combinedshieldtransparent() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let tin1 = DataTransparentInput {
        path: BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap(),
        pk: secp256k1::PublicKey::from_slice(
            hex::decode("031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e")
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
        script: Script(hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap()),
        prevout: OutPoint::new([0u8; 32], 0),
        value: Amount::from_u64(60000).unwrap(),
    };

    let tout1 = DataTransparentOutput {
        value: Amount::from_u64(10000).unwrap(),
        script_pubkey: Script(hex::decode("76a914000000000000000000000000000000000000000088ac").unwrap()),
    };

    let address = PaymentAddress::from_bytes(&[
        198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54, 13, 249, 93, 202, 223, 140,
        15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18, 208, 102, 86, 114, 110, 162, 118, 103,
    ])
    .unwrap();
    let d = *address.diversifier();

    let spend1 = DataShieldedSpend {
        path: 1000,
        note: Note {
            value: 50000,
            g_d: d.g_d().unwrap(),
            pk_d: *address.pk_d(),
            rseed: Rseed::AfterZip212([0u8; 32]),
        },
        diversifier: d,
        witness: IncrementalWitness::read(
            &hex::decode(
                "0102cda01d86b1a443f4012e639556616fa4638233b93a61d12bd30c38ca678d69000101fef93fadf0bfbd769ec217949b45ca5fef3f1b6ae2aebdfbfac8a5f29cd9e24901d0282378d8c5c23edd6be1a5ab023ab608c3ba21411dd7824dd1f52ad074382a00",
            )
            .unwrap()[..],
        )
        .unwrap()
        .path()
        .unwrap(),
    };

    let output1 = DataShieldedOutput {
        value: Amount::from_u64(60000).unwrap(),
        address: PaymentAddress::from_bytes(&[
            21, 234, 231, 0, 224, 30, 36, 226, 19, 125, 85, 77, 103, 187, 13, 166, 78, 238, 11, 241, 194, 195, 146,
            197, 241, 23, 58, 151, 155, 174, 184, 153, 102, 56, 8, 205, 34, 237, 141, 242, 117, 102, 204,
        ])
        .unwrap(),
        ovk: None,
        memo: None,
    };

    let fee = 1000;

    let txfee = Amount::from_u64(fee).unwrap();
    let change_amount = Amount::from_u64(spend1.note.value).unwrap() + tin1.value - tout1.value - output1.value - txfee;
    let change_amount = change_amount.unwrap();

    let output2 = DataShieldedOutput {
        value: change_amount,
        address: PaymentAddress::from_bytes(&[
            198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220, 107, 213, 220, 191, 53, 54, 13, 249, 93, 202, 223,
            140, 15, 162, 93, 203, 237, 170, 246, 5, 117, 56, 184, 18, 208, 102, 86, 114, 110, 162, 118, 103,
        ])
        .unwrap(),
        ovk: Some(OutgoingViewingKey([
            111, 192, 30, 170, 102, 94, 3, 165, 60, 30, 3, 62, 208, 215, 123, 103, 12, 240, 117, 237, 228, 173, 167,
            105, 153, 122, 46, 210, 236, 34, 95, 202,
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

    let r = app
        .do_transaction(input, TestNetwork, consensus::BranchId::Sapling, None, 0)
        .await;
    assert!(r.is_ok());
}

#[tokio::test]
#[serial]
async fn do_full_transaction_transparentonly() {
    init_logging();

    let app = ZcashAppBuilder::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

    let tin1 = DataTransparentInput {
        path: BIP44Path::from_string("m/44'/133'/5'/0/0").unwrap(),
        pk: secp256k1::PublicKey::from_slice(
            hex::decode("031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e")
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
        script: Script(hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap()),
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
        script: Script(hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap()),
        prevout: OutPoint::new([0u8; 32], 0),
        value: Amount::from_u64(40000).unwrap(),
    };

    let tout1 = DataTransparentOutput {
        value: Amount::from_u64(70000).unwrap(),
        script_pubkey: Script(hex::decode("76a914000000000000000000000000000000000000000088ac").unwrap()),
    };

    let fee = 1000;

    let txfee = Amount::from_u64(fee).unwrap();
    let change_amount = tin1.value + tin2.value - tout1.value - txfee;
    let change_amount = change_amount.unwrap();

    let tout2 = DataTransparentOutput {
        value: change_amount,
        script_pubkey: Script(hex::decode("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac").unwrap()),
    };

    let input = DataInput {
        txfee: fee,
        vec_tin: vec![tin1, tin2],
        vec_tout: vec![tout1, tout2],
        vec_sspend: vec![],
        vec_soutput: vec![],
    };

    let r = app
        .do_transaction(input, TestNetwork, consensus::BranchId::Sapling, None, 0)
        .await;
    assert!(r.is_ok());
}
