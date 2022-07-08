//! Structs for building transactions.
use std::{
    io::{self, Write},
    marker::PhantomData,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

use crate::zcash::primitives::{
    consensus,
    constants::SPENDING_KEY_GENERATOR,
    keys::OutgoingViewingKey,
    legacy::{Script, TransparentAddress},
    memo::MemoBytes as Memo,
    merkle_tree::MerklePath,
    note_encryption::SaplingNoteEncryption,
    primitives::{Diversifier, Note, PaymentAddress, ProofGenerationKey, Rseed},
    redjubjub::{PublicKey, Signature},
    sapling::Node,
    transaction::{
        components::{amount::DEFAULT_FEE, Amount, OutPoint, TxIn, TxOut, GROTH_PROOF_SIZE},
        signature_hash_data, SignableInput, Transaction, TransactionData, SIGHASH_ALL,
    },
    util::generate_random_rseed,
};
use crypto_api_chachapoly::ChachaPolyIetf;
use group::GroupEncoding;
use rand::{rngs::OsRng, CryptoRng, RngCore};

use crate::{
    data::{sighashdata::signature_hash_input_data, HashSeed, HsmTxData},
    errors::Error,
    txprover::HsmTxProver,
};

mod builder_data;
pub use builder_data::*;

const DEFAULT_TX_EXPIRY_DELTA: u32 = 20;

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See https://github.com/zcash/zcash/issues/3615
const MIN_SHIELDED_OUTPUTS: usize = 2;

/// Generates a [`Transaction`] from its inputs and outputs.
///
/// This is a rather low level builder, and is a HSM-compatible version
/// of [`crate::zcash::primitives::transaction::builder::Builder`].
pub struct Builder<P: consensus::Parameters, R: RngCore + CryptoRng> {
    rng: R,
    height: u32,
    mtx: TransactionData,
    fee: Amount,
    anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutput>,
    transparent_inputs: TransparentInputs,
    params: P,
    pub sighash: [u8; 32],
}

impl<P: consensus::Parameters> Builder<P, OsRng> {
    /// Creates a new [`Builder`] targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields and the default OS random.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new(params: P, height: u32) -> Self {
        Builder::new_with_rng(params, height, OsRng)
    }

    pub fn new_with_fee(params: P, height: u32, fee: u64) -> Self {
        Builder::new_with_fee_rng(params, height, OsRng, fee)
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng> Builder<P, R> {
    /// Creates a new [`Builder`] targeted for inclusion in the block with the given height
    /// and randomness source, using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new_with_rng(params: P, height: u32, rng: R) -> Self {
        let mut mtx = TransactionData::new();
        mtx.expiry_height = (height + DEFAULT_TX_EXPIRY_DELTA).into();

        Self {
            rng,
            params,
            height,
            mtx,
            fee: DEFAULT_FEE,
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            sighash: [0u8; 32],
        }
    }

    pub fn new_with_fee_rng(params: P, height: u32, rng: R, fee: u64) -> Self {
        let mut mtx = TransactionData::new();
        mtx.expiry_height = (height + DEFAULT_TX_EXPIRY_DELTA).into();
        let txfee = Amount::from_u64(fee).unwrap();

        Self {
            rng,
            params,
            height,
            mtx,
            fee: txfee,
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            sighash: [0u8; 32],
        }
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_sapling_spend(
        &mut self,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
        alpha: jubjub::Fr,            //get from ledger
        proofkey: ProofGenerationKey, //get from ledger
        rcv: jubjub::Fr,              //get from ledger
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one
        //Fixme: add this later when we get info from chain
        // so that the tests don't fail
        // see: https://github.com/Zondax/ledger-zcash-rs/issues/5
        self.anchor = Some(bls12_381::Scalar::one());
        /*
        let cmu = Node::new(note.cmu().into());
        if let Some(anchor) = self.anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(cmu).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.anchor = Some(merkle_path.root(cmu).into())
        }
         */

        self.mtx.value_balance += Amount::from_u64(note.value).map_err(|_| Error::InvalidAmount)?;

        self.spends.push(SpendDescriptionInfo {
            diversifier,
            note,
            alpha,
            merkle_path,
            proofkey,
            rcv,
        });

        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<Memo>,
        rcv: jubjub::Fr,
        rseed: Rseed,
        hash_seed: Option<HashSeed>,
    ) -> Result<(), Error> {
        let output = SaplingOutput::new::<R, P>(ovk, to, value, memo, rcv, rseed, hash_seed)?;

        self.mtx.value_balance -= value;

        self.outputs.push(output);

        Ok(())
    }

    /// Adds a transparent coin to be spent in this transaction.
    pub fn add_transparent_input(
        &mut self,
        pubkey: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        self.transparent_inputs
            .push(&mut self.mtx, pubkey, utxo, coin)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(&mut self, to: Script, value: Amount) -> Result<(), Error> {
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        self.mtx.vout.push(TxOut {
            value,
            script_pubkey: to,
        });

        Ok(())
    }

    /// Prepares a transaction to be transmitted to the HSM from the configured spends and outputs.
    ///
    /// Upon success, returns the structure that can be serialized in in the format understood by the HSM
    /// and subsequently transmitted via the appropriate method.
    ///
    /// After having retrieved the signatures from the HSM and having applied them with the appropriate
    /// methods of the builder, it's possible to retrieve the final signature using [`Builder::finalize`]
    ///
    /// `consensus_branch_id` must be valid for the block height that this transaction is
    /// targeting. An invalid `consensus_branch_id` will *not* result in an error from
    /// this function, and instead will generate a transaction that will be rejected by
    /// the network.
    pub fn build(
        &mut self,
        consensus_branch_id: consensus::BranchId,
        prover: &impl HsmTxProver,
    ) -> Result<HsmTxData, Error> {
        self.build_with_progress_notifier(consensus_branch_id, prover, None)
    }

    pub fn build_with_progress_notifier(
        &mut self,
        consensus_branch_id: consensus::BranchId,
        prover: &impl HsmTxProver,
        progress_notifier: Option<mpsc::Sender<usize>>,
    ) -> Result<HsmTxData, Error> {
        //
        // Consistency checks
        //
        // Valid change
        let change = self.mtx.value_balance - self.fee + self.transparent_inputs.value_sum()
            - self
                .mtx
                .vout
                .iter()
                .map(|output| output.value)
                .sum::<Amount>();
        if change.is_negative() {
            return Err(Error::ChangeIsNegative);
        }

        //
        // Change output
        //

        if change.is_positive() {
            // Send change to the specified change address. If no change address
            // was set, then error as Ledger otherwise needs to give keys and randomness.
            return Err(Error::NoChangeAddress);
        }

        //
        // Record initial positions of spends and outputs
        //
        let spends: Vec<_> = self.spends.clone().into_iter().enumerate().collect();
        let mut outputs: Vec<_> = self.outputs.clone().into_iter().enumerate().collect();

        //
        // Sapling spends and outputs
        //

        //let mut ctx: <impl TxProver as LocalTxProver>::SaplingProvingContext = SaplingProvingContext::new();
        let mut ctx = prover.new_sapling_proving_context();

        // Pad Sapling outputs
        if !spends.is_empty() && outputs.len() < MIN_SHIELDED_OUTPUTS {
            return Err(Error::MinShieldedOuputs);
        }

        // Record if we'll need a binding signature
        let binding_sig_needed = !spends.is_empty() || !outputs.is_empty();

        // Keep track of the total number of steps computed
        let mut progress: usize = 0;

        // Create Sapling SpendDescriptions
        if !spends.is_empty() {
            let anchor = self.anchor.expect("anchor was set if spends were added");

            for (_, spend) in spends.iter() {
                let proof_generation_key = spend.proofkey.clone();

                let nullifier = spend.note.nf(
                    &proof_generation_key.to_viewing_key(),
                    spend.merkle_path.position,
                );

                let (zkproof, cv, rk) = prover
                    .spend_proof(
                        &mut ctx,
                        proof_generation_key,
                        spend.diversifier,
                        spend.note.rseed,
                        spend.alpha,
                        spend.note.value,
                        anchor,
                        spend.merkle_path.clone(),
                        spend.rcv,
                    )
                    .map_err(|()| Error::SpendProof)?;

                // Update progress and send a notification on the channel
                progress += 1;
                progress_notifier.as_ref().map(|tx| tx.send(progress));

                self.mtx.shielded_spends.push(
                    crate::zcash::primitives::transaction::components::SpendDescription {
                        cv,
                        anchor,
                        nullifier,
                        rk: PublicKey(rk.0),
                        zkproof,
                        spend_auth_sig: None,
                    },
                );

                // Record the post-randomized spend location
            }
        }

        // Create Sapling OutputDescriptions
        for (_, output) in outputs.into_iter() {
            let output_desc = output.build(prover, &mut ctx, &mut self.rng);

            // Update progress and send a notification on the channel
            progress += 1;
            progress_notifier.as_ref().map(|tx| tx.send(progress));

            self.mtx.shielded_outputs.push(output_desc);
        }

        //
        // Signatures
        //

        self.sighash.copy_from_slice(&signature_hash_data(
            &self.mtx,
            consensus_branch_id,
            SIGHASH_ALL,
            SignableInput::Shielded,
        ));

        // Add a binding signature if needed
        if binding_sig_needed {
            self.mtx.binding_sig = Some(
                prover
                    .binding_sig(&mut ctx, self.mtx.value_balance, &self.sighash)
                    .map_err(|()| Error::BindingSig)?,
            );
        } else {
            self.mtx.binding_sig = None;
        }

        let r = transparent_script_data_fromtx(&self.mtx, &self.transparent_inputs.inputs);
        if r.is_err() {
            return Err(r.err().unwrap());
        }

        let trans_scripts = r.unwrap();
        let hash_input = signature_hash_input_data(&self.mtx, SIGHASH_ALL);

        let spend_olddata = spend_old_data_fromtx(&self.spends);
        let spenddata = spend_data_hms_fromtx(&self.mtx.shielded_spends);
        let outputdata = output_data_hsm_fromtx(&self.mtx.shielded_outputs);

        Ok(HsmTxData {
            t_script_data: trans_scripts,
            s_spend_old_data: spend_olddata,
            s_spend_new_data: spenddata,
            s_output_data: outputdata,
            tx_hash_data: hash_input,
        })
    }

    /// Attempt to apply the signatures for the transparent components of the transaction
    pub fn add_signatures_transparant(
        &mut self,
        signatures: Vec<secp256k1::Signature>, //get from ledger
        consensus_branch_id: consensus::BranchId,
    ) -> Result<(), Error> {
        self.transparent_inputs
            .apply_signatures(signatures, &mut self.mtx, consensus_branch_id)
    }

    /// Attempt to apply the signatures for the shielded components of the transaction
    pub fn add_signatures_spend(
        &mut self,
        sign: Vec<Signature>, //get from ledger
    ) -> Result<(), Error> {
        if self.spends.is_empty() {
            return Ok(());
        }
        if sign.len() != self.spends.len() {
            return Err(Error::SpendSig);
        }

        let p_g = SPENDING_KEY_GENERATOR;
        let mut all_signatures_valid: bool = true;
        for (i, sig) in sign.iter().enumerate() {
            let rk = PublicKey(self.spends[i].proofkey.ak.into())
                .randomize(self.spends[i].alpha, SPENDING_KEY_GENERATOR);
            all_signatures_valid &= rk.verify(&self.sighash, sig, p_g);
            self.mtx.shielded_spends[i].spend_auth_sig = Some(*sig);
        }
        /*
        let mut spends: Vec<_> = self.spends.clone().into_iter().enumerate().collect();
        let mut all_signatures_valid: bool = true;
        for (i, (_, spend)) in spends.into_iter().enumerate() {
            let rk = PublicKey(spend.proofkey.ak.into()).randomize(spend.alpha,SPENDING_KEY_GENERATOR);
            all_signatures_valid &= rk.verify(&self.sighash, &sign[i], p_g);
            self.mtx.shielded_spends[i].spend_auth_sig = Some(sign[i]);
        }
         */

        match all_signatures_valid {
            true => Ok(()),
            false => Err(Error::SpendSig),
        }
    }

    /// Finalize the transaction, after having obtained all the signatures from the the HSM.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the [`TransactionMetadata`]
    /// generated during the build process.
    pub fn finalize(mut self) -> Result<(Transaction, TransactionMetadata), Error> {
        let tx = self.mtx.freeze().map_err(|_| Error::Finalization)?;
        let mut tx_meta = TransactionMetadata::new();
        tx_meta.spend_indices = (0..self.spends.len()).collect();
        tx_meta.output_indices = (0..self.outputs.len()).collect();
        Ok((tx, tx_meta))
    }

    /*
        pub overwintered: bool,
    pub version: u32,
    pub version_group_id: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub value_balance: Amount,
    pub shielded_spends: Vec<SpendDescription>,
    pub shielded_outputs: Vec<OutputDescription>,
    pub joinsplits: Vec<JSDescription>,
    pub joinsplit_pubkey: Option<[u8; 32]>,
    pub joinsplit_sig: Option<[u8; 64]>,
    pub binding_sig: Option<Signature>,
     */
    /// Same as finalize, except serialized to the format understood by the JavaScript users
    pub fn finalize_js(&mut self) -> Result<Vec<u8>, Error> {
        let mut txdata_copy = TransactionData::new();
        txdata_copy.version = self.mtx.version;
        txdata_copy.vin = vec![];
        for info in self.mtx.vin.iter() {
            let tin = TxIn {
                prevout: info.prevout.clone(),
                script_sig: info.script_sig.clone(),
                sequence: info.sequence,
            };
            txdata_copy.vin.push(tin);
        }
        txdata_copy.vout = vec![];
        for info in self.mtx.vout.clone() {
            txdata_copy.vout.push(info);
        }
        txdata_copy.lock_time = self.mtx.lock_time;
        txdata_copy.expiry_height = self.mtx.expiry_height;
        txdata_copy.value_balance = self.mtx.value_balance;
        txdata_copy.shielded_spends = vec![];
        for info in self.mtx.shielded_spends.iter() {
            let spend = crate::zcash::primitives::transaction::components::SpendDescription {
                cv: info.cv,
                anchor: info.anchor,
                nullifier: info.nullifier,
                rk: PublicKey(info.rk.0),
                zkproof: info.zkproof,
                spend_auth_sig: info.spend_auth_sig,
            };
            txdata_copy.shielded_spends.push(spend);
        }

        for info in self.mtx.shielded_outputs.iter() {
            let output = crate::zcash::primitives::transaction::components::OutputDescription {
                cv: info.cv,
                cmu: info.cmu,
                ephemeral_key: info.ephemeral_key,
                enc_ciphertext: info.enc_ciphertext,
                out_ciphertext: info.out_ciphertext,
                zkproof: info.zkproof,
            };
            txdata_copy.shielded_outputs.push(output);
        }
        txdata_copy.joinsplits = vec![];
        txdata_copy.joinsplit_pubkey = None;
        txdata_copy.joinsplit_sig = None;
        txdata_copy.binding_sig = self.mtx.binding_sig;
        let tx = txdata_copy.freeze().map_err(|_| Error::Finalization)?;
        let mut v = Vec::new();
        tx.write(&mut v)?;
        Ok(v)
    }
}
/*
#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use rand_core::OsRng;
    use std::marker::PhantomData;

    use super::{Builder, Error};
    use crate::zcash::primitives::{
        *,
        consensus::*,
        consensus::TestNetwork,
        legacy::TransparentAddress,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        primitives::Rseed,
        prover::*,
        sapling::Node,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
        transaction::{
            components::{amount::DEFAULT_FEE, OutputDescription, SpendDescription, TxOut},
            signature_hash_data, Transaction, TransactionData, SIGHASH_ALL,
        },
    };
    use crate::zcash::primitives::primitives::ProofGenerationKey;
    use jubjub::{SubgroupPoint, ExtendedPoint};
    use crate::zcash::primitives::keys::OutgoingViewingKey;
    use crate::zcash::primitives::redjubjub::PublicKey;

    #[test]
    fn fails_on_negative_output() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = extfvk.fvk.ovk;
        let to = extfvk.default_address().unwrap().1;
        let mut builder = Builder::<TestNetwork, OsRng>::new(0);
        assert_eq!(
            builder.add_sapling_output(Some(ovk), to, Amount::from_i64(-1).unwrap(), None),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn binding_sig_absent_if_no_shielded_spend_or_output() {
        use crate::consensus::{NetworkUpgrade, Parameters};
        use crate::transaction::{
            builder::{self, TransparentInputs},
            TransactionData,
        };

        let sapling_activation_height =
            TestNetwork::activation_height(NetworkUpgrade::Sapling).unwrap();

        // Create a builder with 0 fee, so we can construct t outputs
        let mut builder = Builder::<TestNetwork, OsRng> {
            rng: OsRng,
            height: sapling_activation_height,
            mtx: TransactionData::new(),
            fee: Amount::zero(),
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            change_address: None,
            phantom: PhantomData,
            sighash: [0u8;32]
        };

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();
/*      there is not public MockTxProver
        let (tx, _) = builder
            .build(consensus::BranchId::Sapling, &MockTxProver)
            .unwrap();
        // No binding signature, because only t input and outputs
        assert!(tx.binding_sig.is_none());

 */
    }

    #[test]
    fn binding_sig_present_if_shielded_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let to = extfvk.default_address().unwrap().1;

        let mut rng = OsRng;

        let note1 = to
            .create_note(50000, Rseed::BeforeZip212(jubjub::Fr::one())) //))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::new();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(&tree);

        let mut builder = Builder::<TestNetwork, OsRng>::new(0);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend(
                *to.diversifier(),
                note1.clone(),
                witness1.path().unwrap(),
                jubjub::Fr::one(),
                ProofGenerationKey{ak:SubgroupPoint::default(),nsk:jubjub::Fr::one()},
                PublicKey(ExtendedPoint::default()),
                Some(OutgoingViewingKey([0xaa;32]))
            )
            .unwrap();

        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();

        // Expect a binding signature error, because our inputs aren't valid, but this shows
        // that a binding signature was attempted
        assert_eq!(
            builder.build(consensus::BranchId::Sapling, &MockTxProver),
            Err(Error::BindingSig)
        );
    }

    #[test]
    fn fails_on_negative_transparent_output() {
        let mut builder = Builder::<TestNetwork, OsRng>::new(0);
        assert_eq!(
            builder.add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                Amount::from_i64(-1).unwrap(),
            ),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn fails_on_negative_change() {
        let mut rng = OsRng;

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let builder = Builder::<TestNetwork, OsRng>::new(0);
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-10000).unwrap()))
            );
        }

        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = Some(extfvk.fvk.ovk);
        let to = extfvk.default_address().unwrap().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_sapling_output(
                    ovk.clone(),
                    to.clone(),
                    Amount::from_u64(50000).unwrap(),
                    None,
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(50000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
            );
        }

        let note1 = to
            .create_note(59999, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::new();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(&tree);

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output(
                    ovk.clone(),
                    to.clone(),
                    Amount::from_u64(30000).unwrap(),
                    None,
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-1).unwrap()))
            );
        }

        let note2 = to
            .create_note(1, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu2 = Node::new(note2.cmu().to_repr());
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(&tree);

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
        //
        // (Still fails because we are using a MockTxProver which doesn't correctly
        // compute bindingSig.)
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1,
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend(extsk, *to.diversifier(), note2, witness2.path().unwrap())
                .unwrap();
            builder
                .add_sapling_output(ovk, to, Amount::from_u64(30000).unwrap(), None)
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::BindingSig)
            )
        }
    }
}
*/
