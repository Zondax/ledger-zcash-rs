use std::path::Path;

use ledger_zcash_app_builder::builder::Builder as ZcashBuilder;
use ledger_zcash_chain_builder::{txbuilder::Builder, txprover};
use zcash_primitives::{
    consensus::{self, TestNetwork},
    transaction::TxVersion,
};

mod types;

const SPEND_PATH: &str = "tests/params/sapling-spend.params";
const OUTPUT_PATH: &str = "tests/params/sapling-output.params";
const TX_VERSION: usize = 5;

// Simulate a transaction where Alice sends 55000 ZEC to Bob. Includes:
// - Two spend notes of 50000 ZEC each, associated with Alice's address at path: 1000.
// - Two output notes for transaction distribution.
// - A transaction fee compliant with ZIP-0317.
// Transaction data is collected from the UI and formatted into JSON structures.
fn test_tx_1(
    data: &types::InitData,
    spendpath: &String,
    outputpath: &String,
    tx_version: u8,
) {
    let tx_ver = match tx_version {
        4 => Some(TxVersion::Sapling),
        5 => Some(TxVersion::Zip225),
        _ => None,
    };

    let n_tin = data.t_in.len();
    let n_tout = data.t_out.len();
    let n_spend = data.s_spend.len();
    let n_sout = data.s_output.len();

    println!("n_tin: {}, n_tout: {}, n_spent: {}, n_sout: {}", n_tin, n_tout, n_spend, n_sout);

    let fee: u64 = ZcashBuilder::calculate_zip0317_fee(n_tin, n_tout, n_spend, n_sout).into();
    println!("Fee: {}", fee);
    let mut builder = Builder::new_with_fee(TestNetwork, 0, fee);
    let prover = txprover::LocalTxProver::new(Path::new(spendpath), Path::new(outputpath));

    builder
        .build(consensus::BranchId::Nu5, tx_ver, &prover)
        .unwrap();
}

#[test]
fn test_tx_builder_fee() {
    let json_data = std::fs::read_to_string("tests/data.json").expect("Failed to read JSON file");
    let test_data: Vec<types::InitData> = serde_json::from_str(&json_data).expect("Failed to parse JSON data");

    // Test No. 1
    test_tx_1(&test_data[0], &SPEND_PATH.to_string(), &OUTPUT_PATH.to_string(), TX_VERSION as u8);

    println!("test_data: {:?}", test_data);
}
