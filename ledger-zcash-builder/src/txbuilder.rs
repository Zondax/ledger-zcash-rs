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
//! Structs for building transactions.
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::{
    io::{self, Write},
    marker::PhantomData,
};

use group::GroupEncoding;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use zcash_note_encryption::NoteEncryption;
use zcash_primitives::transaction::builder::Progress;
use zcash_primitives::{
    consensus::{self, BranchId},
    constants::SPENDING_KEY_GENERATOR,
    keys::OutgoingViewingKey,
    legacy::{Script, TransparentAddress},
    memo::MemoBytes as Memo,
    merkle_tree::MerklePath,
    sapling::{
        note_encryption::sapling_note_encryption,
        redjubjub::{PublicKey, Signature},
        util::generate_random_rseed,
        Diversifier, Node, Note, PaymentAddress, ProofGenerationKey, Rseed,
    },
    transaction::{
        self,
        components::{amount::DEFAULT_FEE, sapling, transparent, Amount, OutPoint, TxIn, TxOut, GROTH_PROOF_SIZE},
        sighash::{signature_hash, SignableInput, SIGHASH_ALL},
        txid::TxIdDigester,
        Authorization, Transaction, TransactionData, TxDigests, TxVersion, Unauthorized,
    },
};

use crate::{
    data::{sighashdata::signature_hash_input_data, HashSeed, HsmTxData},
    errors::Error,
    txprover::HsmTxProver,
};

mod builder_data;
pub use builder_data::*;

/// Contains utilities to aid transaction building in a HSM context
pub mod hsmauth;
use hsmauth::MixedAuthorization;

const DEFAULT_TX_EXPIRY_DELTA: u32 = 20;

/// If there are any shielded inputs, always have at least two shielded outputs,
/// padding with dummy outputs if necessary. See https://github.com/zcash/zcash/issues/3615
const MIN_SHIELDED_OUTPUTS: usize = 2;

/// Generates a [`Transaction`] from its inputs and outputs.
///
/// This is a rather low level builder, and is a HSM-compatible version
/// of [`crate::zcash::primitives::transaction::builder::Builder`].
pub struct Builder<P: consensus::Parameters, R: RngCore + CryptoRng, A: Authorization> {
    rng: R,
    height: u32,
    fee: Amount,
    anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutput>,
    params: P,
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    sapling_bundle: Option<sapling::Bundle<A::SaplingAuth>>,
    binding_sig: Option<Signature>,
    cached_branchid: Option<BranchId>,
    cached_tx_version: Option<TxVersion>,
}

impl<P: consensus::Parameters> Builder<P, OsRng, hsmauth::Unauthorized> {
    /// Creates a new [`Builder`] targeted for inclusion in the block with the
    /// given height, using default values for general transaction fields
    /// and the default OS random.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default
    /// transaction expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new(
        params: P,
        height: u32,
    ) -> Self {
        Builder::new_with_rng(params, height, OsRng)
    }

    pub fn new_with_fee(
        params: P,
        height: u32,
        fee: u64,
    ) -> Self {
        Builder::new_with_fee_rng(params, height, OsRng, fee)
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng> Builder<P, R, hsmauth::Unauthorized> {
    /// Creates a new [`Builder`] targeted for inclusion in the block with the
    /// given height and randomness source, using default values for general
    /// transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default
    /// transaction expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new_with_rng(
        params: P,
        height: u32,
        rng: R,
    ) -> Self {
        Self {
            rng,
            params,
            height,
            fee: DEFAULT_FEE,
            anchor: None,
            spends: vec![],
            outputs: vec![],
            cached_branchid: None,
            cached_tx_version: None,
            binding_sig: None,
            transparent_bundle: None,
            sapling_bundle: None,
        }
    }

    pub fn new_with_fee_rng(
        params: P,
        height: u32,
        rng: R,
        fee: u64,
    ) -> Self {
        let mut this = Self::new_with_rng(params, height, rng);
        this.fee = Amount::from_u64(fee).unwrap();

        this
    }
}

impl<P, R, A> Builder<P, R, A>
where
    P: consensus::Parameters,
    R: RngCore + CryptoRng,
    A: Authorization,
    A::TransparentAuth: Clone,
    A::SaplingAuth: Clone,
{
    /// Retrieve the [`TransactionData`] of the current builder state
    pub fn transaction_data(&self) -> Option<TransactionData<A>> {
        let optionals = self
            .cached_tx_version
            .zip(self.cached_branchid);
        optionals.map(|(cached_tx_version, consensus_branch_id)| {
            TransactionData::from_parts(
                cached_tx_version,
                consensus_branch_id,
                0,
                (self.height + DEFAULT_TX_EXPIRY_DELTA).into(),
                self.transparent_bundle.clone(),
                None,
                self.sapling_bundle.clone(),
                None,
            )
        })
    }
}

impl<P, R, TA, SA, A> Builder<P, R, A>
where
    P: consensus::Parameters,
    R: RngCore + CryptoRng,
    TA: Clone + transaction::sighash::TransparentAuthorizingContext,
    SA: Clone + sapling::Authorization<Proof = sapling::GrothProofBytes>,
    A: Authorization<SaplingAuth = SA, TransparentAuth = TA>,
{
    //noinspection RsNonExhaustiveMatch
    /// Retrieve the sighash of the current builder state
    fn signature_hash(&self) -> Option<[u8; 32]> {
        let data = self.transaction_data()?;
        let txid_parts = data.digest(TxIdDigester);

        let sighash = match data.version() {
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
                transaction::sighash_v4::v4_signature_hash(&data, &SignableInput::Shielded)
            },
            TxVersion::Zip225 => {
                transaction::sighash_v5::v5_signature_hash(&data, &SignableInput::Shielded, &txid_parts)
            },
        };

        let mut array = [0; 32];
        array.copy_from_slice(&sighash.as_ref()[.. 32]);
        Some(array)
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng, TA: transparent::Authorization>
    Builder<P, R, MixedAuthorization<TA, hsmauth::sapling::Unauthorized>>
{
    fn empty_sapling_bundle() -> sapling::Bundle<hsmauth::sapling::Unauthorized> {
        sapling::Bundle {
            shielded_spends: vec![],
            shielded_outputs: vec![],
            value_balance: Amount::zero(),
            authorization: Default::default(),
        }
    }

    fn sapling_bundle(&mut self) -> &mut sapling::Bundle<hsmauth::sapling::Unauthorized> {
        self.sapling_bundle
            .get_or_insert_with(|| Self::empty_sapling_bundle())
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor
    /// as the paths for previous Sapling notes.
    pub fn add_sapling_spend(
        &mut self,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
        alpha: jubjub::Fr,            // get from ledger
        proofkey: ProofGenerationKey, // get from ledger
        rcv: jubjub::Fr,              // get from ledger
    ) -> Result<(), Error> {
        log::info!("Adding Sapling spend");
        // Consistency check: all anchors must equal the first one
        let cmu = Node::new(note.cmu().into());
        if let Some(anchor) = self.anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(cmu).into();
            if path_root != anchor {
                log::error!("Anchor mismatch");
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.anchor = Some(merkle_path.root(cmu).into())
        }

        self.sapling_bundle().value_balance += Amount::from_u64(note.value).map_err(|_| Error::InvalidAmount)?;

        let description = SpendDescriptionInfo { diversifier, note, alpha, merkle_path, proofkey, rcv };

        self.spends.push(description);

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

        self.sapling_bundle().value_balance -= value;

        self.outputs.push(output);

        Ok(())
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng, SA: sapling::Authorization>
    Builder<P, R, MixedAuthorization<hsmauth::transparent::Unauthorized, SA>>
{
    fn empty_transparent_bundle() -> transparent::Bundle<hsmauth::transparent::Unauthorized> {
        transparent::Bundle { vin: vec![], vout: vec![], authorization: Default::default() }
    }

    /// Retrieve the transaction's transparent bundle
    ///
    /// Will initialize an empty one if not present
    fn transparent_bundle(&mut self) -> &mut transparent::Bundle<hsmauth::transparent::Unauthorized> {
        self.transparent_bundle
            .get_or_insert_with(|| Self::empty_transparent_bundle())
    }

    /// Adds a transparent coin to be spent in this transaction.
    pub fn add_transparent_input(
        &mut self,
        pubkey: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        log::info!("add_transparent_input");

        if coin.value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKey(hash)) => {
                use ripemd::{Digest as _, Ripemd160};
                use sha2::{Digest as _, Sha256};

                if hash[..] != Ripemd160::digest(Sha256::digest(pubkey.serialize()))[..] {
                    return Err(Error::InvalidAddressHash);
                }
            },
            _ => return Err(Error::InvalidAddressFormat),
        }

        let bundle = self.transparent_bundle();

        // TxIn is made like this to trick the compiler
        // in assigning the correct Authorization generic
        // parameter, since `vin` uses the primitives' Unauthorized
        // whilst we use the one in hsmauth
        let vin = TxIn::new(utxo);
        bundle
            .vin
            .push(TxIn { script_sig: vin.script_sig, sequence: vin.sequence, prevout: vin.prevout });
        bundle
            .authorization
            .inputs
            .push(TransparentInputInfo { pubkey, coin });

        Ok(())
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(
        &mut self,
        to: Script,
        value: Amount,
    ) -> Result<(), Error> {
        log::info!("add_transparent_output");
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        self.transparent_bundle()
            .vout
            .push(TxOut { value, script_pubkey: to });

        Ok(())
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng>
    Builder<P, R, MixedAuthorization<hsmauth::transparent::Unauthorized, hsmauth::sapling::Unauthorized>>
{
    /// Prepares a transaction to be transmitted to the HSM from the configured
    /// spends and outputs.
    ///
    /// Upon success, returns the structure that can be serialized in the
    /// format understood by the HSM and subsequently transmitted via the
    /// appropriate method.
    ///
    /// After having retrieved the signatures from the HSM and having applied
    /// them with the appropriate methods of the builder, it's possible to
    /// retrieve the final signature using [`Builder::finalize`]
    ///
    /// `consensus_branch_id` must be valid for the block height that this
    /// transaction is targeting. An invalid `consensus_branch_id` will
    /// *not* result in an error from this function, and instead will
    /// generate a transaction that will be rejected by the network.
    pub fn build(
        &mut self,
        consensus_branch_id: consensus::BranchId,
        tx_version: Option<TxVersion>,
        prover: &impl HsmTxProver,
    ) -> Result<HsmTxData, Error> {
        self.build_with_progress_notifier(consensus_branch_id, tx_version, prover, None)
    }

    pub fn build_with_progress_notifier(
        &mut self,
        consensus_branch_id: BranchId,
        tx_version: Option<TxVersion>,
        prover: &impl HsmTxProver,
        progress_notifier: Option<Sender<Progress>>,
    ) -> Result<HsmTxData, Error> {
        log::info!("build_with_progress_notifier");
        self.cached_branchid
            .replace(consensus_branch_id);

        let tx_version = match tx_version {
            Some(v) => v,
            None => TxVersion::suggested_for_branch(consensus_branch_id),
        };

        self.cached_tx_version
            .replace(tx_version);

        // Consistency checks
        // Valid change
        let sapling_value = self
            .sapling_bundle
            .as_ref()
            .map(|bundle| bundle.value_balance)
            .unwrap_or(Amount::zero());
        let input_value = self
            .transparent_bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .authorization
                    .inputs
                    .iter()
                    .map(|input| input.coin.value)
                    // poor man's .sum
                    .fold(Amount::zero(), |x, acc| (x + acc).unwrap())
            })
            .unwrap_or(Amount::zero());
        let output_value = self
            .transparent_bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .vout
                    .iter()
                    .map(|output| output.value)
                    .fold(Amount::zero(), |x, acc| (x + acc).unwrap())
            })
            .unwrap_or(Amount::zero());

        log::debug!("Sapling value: {:?}", sapling_value);
        log::debug!("Input value: {:?}", input_value);
        log::debug!("Output value: {:?}", output_value);
        log::debug!("Fee: {:?}", self.fee);

        let change = sapling_value + input_value - output_value - self.fee;
        let change = change.unwrap();
        log::debug!("Change: {:?}", change);

        if change.is_negative() {
            log::error!("Change is negative {:?}", change);
            return Err(Error::ChangeIsNegative);
        }

        // Change output
        if change.is_positive() {
            // Send change to the specified change address. If no change address
            // was set, then error as Ledger otherwise needs to give keys and randomness.
            log::error!("No change address");
            return Err(Error::NoChangeAddress);
        }

        // Record initial positions of spends and outputs
        //
        let spends: Vec<_> = self
            .spends
            .clone()
            .into_iter()
            .enumerate()
            .collect();
        let mut outputs: Vec<_> = self
            .outputs
            .clone()
            .into_iter()
            .enumerate()
            .collect();

        // Sapling spends and outputs
        //

        // let mut ctx: <impl TxProver as LocalTxProver>::SaplingProvingContext =
        // SaplingProvingContext::new();
        let mut ctx = prover.new_sapling_proving_context();

        // Pad Sapling outputs
        if !spends.is_empty() && outputs.len() < MIN_SHIELDED_OUTPUTS {
            log::error!("Not enough shielded outputs");
            return Err(Error::MinShieldedOutputs);
        }

        // Record if we'll need a binding signature
        let binding_sig_needed = !spends.is_empty() || !outputs.is_empty();

        // Keep track of the total number of steps computed
        let mut progress = 0u32;

        // Create Sapling SpendDescriptions
        if !spends.is_empty() {
            let anchor = self
                .anchor
                .expect("anchor was set if spends were added");

            for (_, spend) in spends.into_iter() {
                let proof_generation_key = spend.proofkey.clone();

                let nullifier = spend
                    .note
                    .nf(&proof_generation_key.to_viewing_key(), spend.merkle_path.position);

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
                    .map_err(|_| Error::SpendProof)?;

                // Update progress and send a notification on the channel
                progress += 1;
                if let Some(sender) = progress_notifier.as_ref() {
                    // If the send fails, we should ignore the error, not crash.
                    let _ = sender.send(Progress::new(progress, None));
                }

                self.sapling_bundle()
                    .shielded_spends
                    .push(sapling::SpendDescription {
                        cv,
                        anchor,
                        nullifier,
                        rk: PublicKey(rk.0),
                        zkproof,
                        spend_auth_sig: spend,
                    });

                // Record the post-randomized spend location
            }
        }

        // Create Sapling OutputDescriptions
        for (_, output) in outputs.into_iter() {
            let output_desc = output.build(prover, &mut ctx, &mut self.rng, &self.params);

            // Update progress and send a notification on the channel
            progress += 1;
            if let Some(sender) = progress_notifier.as_ref() {
                // If the send fails, we should ignore the error, not crash.
                let _ = sender.send(Progress::new(progress, None));
            }

            self.sapling_bundle()
                .shielded_outputs
                .push(output_desc);
        }

        // Signatures -- everything but the signatures must already have been added.
        // Add a binding signature if needed
        if binding_sig_needed {
            let signature_hash = self
                .signature_hash()
                .ok_or(Error::BindingSig)?;

            self.binding_sig = Some(
                prover
                    .binding_sig(&mut ctx, self.sapling_bundle().value_balance, &signature_hash)
                    .map_err(|_| Error::BindingSig)?,
            );
        } else {
            self.binding_sig = None;
        }

        let r = transparent_script_data_fromtx(
            self.transparent_bundle
                .as_ref()
                .map(|bundle| bundle.vin.as_slice())
                .unwrap_or(&[]),
            self.transparent_bundle
                .as_ref()
                .map(|bundle| bundle.authorization.inputs.as_slice())
                .unwrap_or(&[]),
        );
        if r.is_err() {
            return Err(r.err().unwrap());
        }

        let trans_scripts = r.unwrap();
        let hash_input = signature_hash_input_data(&self.transaction_data().unwrap(), SIGHASH_ALL);

        let spend_olddata = spend_old_data_fromtx(&self.spends);
        let spenddata = spend_data_hms_fromtx(
            self.sapling_bundle
                .as_ref()
                .map(|bundle| bundle.shielded_spends.as_slice())
                .unwrap_or(&[]),
        );
        let outputdata = output_data_hsm_fromtx(
            self.sapling_bundle
                .as_ref()
                .map(|bundle| bundle.shielded_outputs.as_slice())
                .unwrap_or(&[]),
        );

        Ok(HsmTxData {
            t_script_data: trans_scripts,
            s_spend_old_data: spend_olddata,
            s_spend_new_data: spenddata,
            s_output_data: outputdata,
            tx_hash_data: hash_input,
        })
    }
}

impl<P, R, SA> Builder<P, R, MixedAuthorization<hsmauth::transparent::Unauthorized, SA>>
where
    P: consensus::Parameters,
    R: RngCore + CryptoRng,
    SA: sapling::Authorization<Proof = sapling::GrothProofBytes> + Clone,
{
    /// convenience wrapper to switch transparent bundle associated parameter
    fn with_transparent_bundle<TA: transparent::Authorization>(
        self,
        bundle: Option<transparent::Bundle<TA>>,
    ) -> Builder<P, R, MixedAuthorization<TA, SA>> {
        let Self {
            rng,
            height,
            fee,
            anchor,
            spends,
            outputs,
            params,
            transparent_bundle: _,
            sapling_bundle,
            binding_sig,
            cached_branchid,
            cached_tx_version,
        } = self;

        Builder {
            rng,
            height,
            fee,
            anchor,
            spends,
            outputs,
            params,
            transparent_bundle: bundle,
            sapling_bundle,
            binding_sig,
            cached_branchid,
            cached_tx_version,
        }
    }

    //noinspection RsNonExhaustiveMatch
    /// Attempt to apply the signatures for the transparent components of the
    /// transaction
    pub fn add_signatures_transparent(
        self,
        signatures: Vec<secp256k1::ecdsa::Signature>, // get from ledger
    ) -> Result<Builder<P, R, MixedAuthorization<transparent::Authorized, SA>>, Error> {
        let tx_data = self
            .transaction_data()
            .expect("consensus branch id set");
        let transparent::Bundle { vin, vout, authorization } =
            match (self.transparent_bundle.as_ref(), signatures.len()) {
                (None, 0) => return Ok(self.with_transparent_bundle(None)),
                (None, _) => return Err(Error::TransparentSig),
                // this check takes into account also when we have no inputs
                // since we don't have inputs we also get 0 signatures
                // and below the other if will take care of skipping the
                // signature verifications etc
                (Some(bundle), n) if n != bundle.authorization.inputs.len() => {
                    log::error!("Transparent signatures necessary #{}, got #{}", bundle.authorization.inputs.len(), n);
                    return Err(Error::TransparentSig);
                },
                (Some(bundle), _) => bundle,
            };

        let mut bundle: transparent::Bundle<transparent::Authorized> = transparent::Bundle {
            vin: Vec::with_capacity(vin.len()),
            vout: vout.clone(),
            authorization: transparent::Authorized,
        };

        if !authorization.inputs.is_empty() {
            for (i, ((info, sig), vin)) in authorization
                .inputs
                .iter()
                .zip(signatures.into_iter())
                .zip(vin.iter())
                .enumerate()
            {
                // 1) generate the signature message
                // to verify the signature against
                let sighash = match tx_data.version() {
                    TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
                        transaction::sighash_v4::v4_signature_hash(&tx_data, &SignableInput::Transparent {
                            hash_type: SIGHASH_ALL,
                            index: i,
                            value: info.coin.value,
                            script_pubkey: &info.coin.script_pubkey,
                            // for p2pkh, always the same as script_pubkey
                            script_code: &info.coin.script_pubkey,
                        })
                    },
                    TxVersion::Zip225 => {
                        let txid_parts = tx_data.digest(TxIdDigester);
                        transaction::sighash_v5::v5_signature_hash(
                            &tx_data,
                            &SignableInput::Transparent {
                                hash_type: SIGHASH_ALL,
                                index: i,
                                value: info.coin.value,
                                script_pubkey: &info.coin.script_pubkey,
                                // for p2pkh, always the same as script_pubkey
                                script_code: &info.coin.script_pubkey,
                            },
                            &txid_parts,
                        )
                    },
                };

                let msg = secp256k1::Message::from_slice(sighash.as_ref()).expect("32 bytes");

                // 2) verify signature
                if authorization
                    .secp
                    .verify_ecdsa(&msg, &sig, &info.pubkey)
                    .is_err()
                {
                    log::error!("Error verifying transparent sig #{}", i);
                    return Err(Error::TransparentSig);
                }

                // Signature has to have "SIGHASH_ALL" appended to it
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend(&[SIGHASH_ALL]);

                // save P2PKH scriptSig
                let script_sig = Script::default() << &sig_bytes[..] << &info.pubkey.serialize()[..];

                bundle
                    .vin
                    .push(TxIn { prevout: vin.prevout.clone(), script_sig, sequence: vin.sequence })
            }
        }

        Ok(self.with_transparent_bundle(Some(bundle)))
    }
}

impl<P, R, TA> Builder<P, R, MixedAuthorization<TA, hsmauth::sapling::Unauthorized>>
where
    P: consensus::Parameters,
    R: RngCore + CryptoRng,
    TA: transparent::Authorization + transaction::sighash::TransparentAuthorizingContext + Clone,
{
    /// convenience wrapper to switch transparent bundle associated parameter
    fn with_sapling_bundle<SA: sapling::Authorization>(
        self,
        bundle: Option<sapling::Bundle<SA>>,
    ) -> Builder<P, R, MixedAuthorization<TA, SA>> {
        let Self {
            rng,
            height,
            fee,
            anchor,
            spends,
            outputs,
            params,
            transparent_bundle,
            sapling_bundle: _,
            binding_sig,
            cached_branchid,
            cached_tx_version,
        } = self;

        Builder {
            rng,
            height,
            fee,
            anchor,
            spends,
            outputs,
            params,
            transparent_bundle,
            sapling_bundle: bundle,
            binding_sig,
            cached_branchid,
            cached_tx_version,
        }
    }
    /// Attempt to apply the signatures for the shielded components of the
    /// transaction
    pub fn add_signatures_spend(
        self,
        signatures: Vec<Signature>, // get from ledger
    ) -> Result<Builder<P, R, MixedAuthorization<TA, sapling::Authorized>>, Error> {
        let sapling::Bundle { shielded_spends, shielded_outputs, value_balance, .. } =
            match (self.sapling_bundle.as_ref(), signatures.len()) {
                (None, 0) => return Ok(self.with_sapling_bundle(None)),
                (None, _) => return Err(Error::NoSpendSig),
                // if we have no inputs and no signatures were passed this succeeds
                (Some(_), n) if n != self.spends.len() => {
                    log::error!("Sapling signatures necessary #{}, got #{}", self.spends.len(), n);
                    return Err(Error::MissingSpendSig);
                },
                (Some(bundle), _) => bundle,
            };

        let Self { spends, .. } = &self;

        let mut sapling_bundle = sapling::Bundle {
            shielded_spends: Vec::with_capacity(spends.len()),
            shielded_outputs: shielded_outputs.clone(),
            value_balance: *value_balance,
            authorization: sapling::Authorized {
                // if we reach here without binding sig it's an error
                // since if we had spends or outputs (so no binding sig needed)
                // we would have returned already from the method
                binding_sig: self.binding_sig.ok_or_else(|| {
                    log::error!("no binding signature");
                    Error::BindingSig
                })?,
            },
        };

        let mut all_signatures_valid: bool = true;

        // if we have no spends we can just skip
        // applying the signatures and verifying
        if !spends.is_empty() {
            let sighash = self
                .signature_hash()
                .ok_or(Error::InvalidSpendSig)?;

            let p_g = SPENDING_KEY_GENERATOR;
            for (i, ((spend_auth_sig, spendinfo), spend)) in signatures
                .into_iter()
                .zip(spends.iter())
                .zip(shielded_spends.iter())
                .enumerate()
            {
                let ak = spendinfo.proofkey.ak;
                let rk = PublicKey(ak.into()).randomize(spendinfo.alpha, SPENDING_KEY_GENERATOR);

                let message = {
                    let mut array = [0; 64];
                    array[.. 32].copy_from_slice(&rk.0.to_bytes());
                    array[32 ..].copy_from_slice(&sighash[..]);
                    array
                };

                let valid = rk.verify(&message, &spend_auth_sig, p_g);

                all_signatures_valid &= valid;

                let spend = sapling::SpendDescription {
                    spend_auth_sig,
                    cv: spend.cv,
                    anchor: spend.anchor,
                    nullifier: spend.nullifier,
                    rk,
                    zkproof: spend.zkproof,
                };
                sapling_bundle
                    .shielded_spends
                    .push(spend);
            }
            // let mut spends: Vec<_> =
            // self.spends.clone().into_iter().enumerate().collect();
            // let mut all_signatures_valid: bool = true;
            // for (i, (_, spend)) in spends.into_iter().enumerate() {
            // let rk = PublicKey(spend.proofkey.ak.into()).randomize(spend.
            // alpha,SPENDING_KEY_GENERATOR); all_signatures_valid
            // &= rk.verify(&self.sighash, &sign[i], p_g);
            // self.mtx.shielded_spends[i].spend_auth_sig = Some(sign[i]);
            // }
        }

        match all_signatures_valid {
            true => {
                let mut this = self.with_sapling_bundle(Some(sapling_bundle));
                this.spends = vec![];
                this.outputs = vec![];

                Ok(this)
            },
            false => Err(Error::InvalidSpendSig),
        }
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng>
    Builder<P, R, MixedAuthorization<transparent::Authorized, sapling::Authorized>>
{
    /// Retrieve [`TransactionData`] parametrized with
    /// [`transaction::Authorized`]
    fn transaction_data_authorized(&self) -> Option<TransactionData<transaction::Authorized>> {
        let optionals = self
            .cached_tx_version
            .zip(self.cached_branchid);
        optionals.map(|(cached_tx_version, consensus_branch_id)| {
            TransactionData::from_parts(
                cached_tx_version,
                consensus_branch_id,
                0,
                (self.height + DEFAULT_TX_EXPIRY_DELTA).into(),
                self.transparent_bundle.clone(),
                None,
                self.sapling_bundle.clone(),
                None,
            )
        })
    }

    /// Finalize the transaction, after having obtained all the signatures from
    /// the the HSM.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`TransactionMetadata`] generated during the build process.
    pub fn finalize(mut self) -> Result<(Transaction, SaplingMetadata), Error> {
        let tx_data = self
            .transaction_data_authorized()
            .ok_or(Error::Finalization)?;
        let tx = tx_data
            .freeze()
            .map_err(|_| Error::Finalization)?;

        let mut tx_meta = SaplingMetadata::new();
        tx_meta.spend_indices = (0 .. self.spends.len()).collect();
        tx_meta.output_indices = (0 .. self.outputs.len()).collect();
        Ok((tx, tx_meta))
    }

    /// Same as finalize, except serialized to the format understood by the
    /// JavaScript users
    pub fn finalize_js(&mut self) -> Result<Vec<u8>, Error> {
        let txdata = self
            .transaction_data_authorized()
            .ok_or(Error::Finalization)?;
        let tx = txdata
            .freeze()
            .map_err(|_| Error::Finalization)?;

        let mut v = Vec::new();
        tx.write(&mut v)
            .map_err(|_| Error::ReadWriteError)?;
        Ok(v)
    }
}
// #[cfg(test)]
// mod tests {
// use ff::{Field, PrimeField};
// use rand_core::OsRng;
// use std::marker::PhantomData;
//
// use super::{Builder, Error};
// use crate::zcash::primitives::{
// ,
// consensus::*,
// consensus::TestNetwork,
// legacy::TransparentAddress,
// merkle_tree::{CommitmentTree, IncrementalWitness},
// primitives::Rseed,
// prover::*,
// sapling::Node,
// transaction::components::Amount,
// zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
// transaction::{
// components::{amount::DEFAULT_FEE, OutputDescription, SpendDescription,
// TxOut}, signature_hash_data, Transaction, TransactionData, SIGHASH_ALL,
// },
// };
// use crate::zcash::primitives::primitives::ProofGenerationKey;
// use jubjub::{SubgroupPoint, ExtendedPoint};
// use crate::zcash::primitives::keys::OutgoingViewingKey;
// use crate::zcash::primitives::redjubjub::PublicKey;
//
// #[test]
// fn fails_on_negative_output() {
// let extsk = ExtendedSpendingKey::master(&[]);
// let extfvk = ExtendedFullViewingKey::from(&extsk);
// let ovk = extfvk.fvk.ovk;
// let to = extfvk.default_address().unwrap().1;
// let mut builder = Builder::<TestNetwork, OsRng>::new(0);
// assert_eq!(
// builder.add_sapling_output(Some(ovk), to, Amount::from_i64(-1).unwrap(),
// None), Err(Error::InvalidAmount)
// );
// }
//
// #[test]
// fn binding_sig_absent_if_no_shielded_spend_or_output() {
// use crate::consensus::{NetworkUpgrade, Parameters};
// use crate::transaction::{
// builder::{self, TransparentInputs},
// TransactionData,
// };
//
// let sapling_activation_height =
// TestNetwork::activation_height(NetworkUpgrade::Sapling).unwrap();
//
// Create a builder with 0 fee, so we can construct t outputs
// let mut builder = Builder::<TestNetwork, OsRng> {
// rng: OsRng,
// height: sapling_activation_height,
// mtx: TransactionData::new(),
// fee: Amount::zero(),
// anchor: None,
// spends: vec![],
// outputs: vec![],
// transparent_inputs: TransparentInputs::default(),
// change_address: None,
// phantom: PhantomData,
// sighash: [0u8;32]
// };
//
// Create a tx with only t output. No binding_sig should be present
// builder
// .add_transparent_output(&TransparentAddress::PublicKey([0; 20]),
// Amount::zero()) .unwrap();
//      there is not public MockTxProver
// let (tx, _) = builder
// .build(consensus::BranchId::Sapling, &MockTxProver)
// .unwrap();
// No binding signature, because only t input and outputs
// assert!(tx.binding_sig.is_none());
//
// /
// }
//
// #[test]
// fn binding_sig_present_if_shielded_spend() {
// let extsk = ExtendedSpendingKey::master(&[]);
// let extfvk = ExtendedFullViewingKey::from(&extsk);
// let to = extfvk.default_address().unwrap().1;
//
// let mut rng = OsRng;
//
// let note1 = to
// .create_note(50000, Rseed::BeforeZip212(jubjub::Fr::one())) //))
// .unwrap();
// let cmu1 = Node::new(note1.cmu().to_repr());
// let mut tree = CommitmentTree::new();
// tree.append(cmu1).unwrap();
// let witness1 = IncrementalWitness::from_tree(&tree);
//
// let mut builder = Builder::<TestNetwork, OsRng>::new(0);
//
// Create a tx with a sapling spend. binding_sig should be present
// builder
// .add_sapling_spend(
// to.diversifier(),
// note1.clone(),
// witness1.path().unwrap(),
// jubjub::Fr::one(),
// ProofGenerationKey{ak:SubgroupPoint::default(),nsk:jubjub::Fr::one()},
// PublicKey(ExtendedPoint::default()),
// Some(OutgoingViewingKey([0xaa;32]))
// )
// .unwrap();
//
// builder
// .add_transparent_output(&TransparentAddress::PublicKey([0; 20]),
// Amount::zero()) .unwrap();
//
// Expect a binding signature error, because our inputs aren't valid, but this
// shows that a binding signature was attempted
// assert_eq!(
// builder.build(consensus::BranchId::Sapling, &MockTxProver),
// Err(Error::BindingSig)
// );
// }
//
// #[test]
// fn fails_on_negative_transparent_output() {
// let mut builder = Builder::<TestNetwork, OsRng>::new(0);
// assert_eq!(
// builder.add_transparent_output(
// &TransparentAddress::PublicKey([0; 20]),
// Amount::from_i64(-1).unwrap(),
// ),
// Err(Error::InvalidAmount)
// );
// }
//
// #[test]
// fn fails_on_negative_change() {
// let mut rng = OsRng;
//
// Just use the master key as the ExtendedSpendingKey for this test
// let extsk = ExtendedSpendingKey::master(&[]);
//
// Fails with no inputs or outputs
// 0.0001 t-ZEC fee
// {
// let builder = Builder::<TestNetwork, OsRng>::new(0);
// assert_eq!(
// builder.build(consensus::BranchId::Sapling, &MockTxProver),
// Err(Error::ChangeIsNegative(Amount::from_i64(-10000).unwrap()))
// );
// }
//
// let extfvk = ExtendedFullViewingKey::from(&extsk);
// let ovk = Some(extfvk.fvk.ovk);
// let to = extfvk.default_address().unwrap().1;
//
// Fail if there is only a Sapling output
// 0.0005 z-ZEC out, 0.0001 t-ZEC fee
// {
// let mut builder = Builder::<TestNetwork, OsRng>::new(0);
// builder
// .add_sapling_output(
// ovk.clone(),
// to.clone(),
// Amount::from_u64(50000).unwrap(),
// None,
// )
// .unwrap();
// assert_eq!(
// builder.build(consensus::BranchId::Sapling, &MockTxProver),
// Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
// );
// }
//
// Fail if there is only a transparent output
// 0.0005 t-ZEC out, 0.0001 t-ZEC fee
// {
// let mut builder = Builder::<TestNetwork, OsRng>::new(0);
// builder
// .add_transparent_output(
// &TransparentAddress::PublicKey([0; 20]),
// Amount::from_u64(50000).unwrap(),
// )
// .unwrap();
// assert_eq!(
// builder.build(consensus::BranchId::Sapling, &MockTxProver),
// Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
// );
// }
//
// let note1 = to
// .create_note(59999, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
// .unwrap();
// let cmu1 = Node::new(note1.cmu().to_repr());
// let mut tree = CommitmentTree::new();
// tree.append(cmu1).unwrap();
// let mut witness1 = IncrementalWitness::from_tree(&tree);
//
// Fail if there is insufficient input
// 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
// {
// let mut builder = Builder::<TestNetwork, OsRng>::new(0);
// builder
// .add_sapling_spend(
// extsk.clone(),
// to.diversifier(),
// note1.clone(),
// witness1.path().unwrap(),
// )
// .unwrap();
// builder
// .add_sapling_output(
// ovk.clone(),
// to.clone(),
// Amount::from_u64(30000).unwrap(),
// None,
// )
// .unwrap();
// builder
// .add_transparent_output(
// &TransparentAddress::PublicKey([0; 20]),
// Amount::from_u64(20000).unwrap(),
// )
// .unwrap();
// assert_eq!(
// builder.build(consensus::BranchId::Sapling, &MockTxProver),
// Err(Error::ChangeIsNegative(Amount::from_i64(-1).unwrap()))
// );
// }
//
// let note2 = to
// .create_note(1, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
// .unwrap();
// let cmu2 = Node::new(note2.cmu().to_repr());
// tree.append(cmu2).unwrap();
// witness1.append(cmu2).unwrap();
// let witness2 = IncrementalWitness::from_tree(&tree);
//
// Succeeds if there is sufficient input
// 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
//
// (Still fails because we are using a MockTxProver which doesn't correctly
// compute bindingSig.)
// {
// let mut builder = Builder::<TestNetwork, OsRng>::new(0);
// builder
// .add_sapling_spend(
// extsk.clone(),
// to.diversifier(),
// note1,
// witness1.path().unwrap(),
// )
// .unwrap();
// builder
// .add_sapling_spend(extsk, *to.diversifier(), note2, witness2.path().unwrap())
// .unwrap();
// builder
// .add_sapling_output(ovk, to, Amount::from_u64(30000).unwrap(), None)
// .unwrap();
// builder
// .add_transparent_output(
// &TransparentAddress::PublicKey([0; 20]),
// Amount::from_u64(20000).unwrap(),
// )
// .unwrap();
// assert_eq!(
// builder.build(consensus::BranchId::Sapling, &MockTxProver),
// Err(Error::BindingSig)
// )
// }
// }
// }
