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
//! Abstractions over the proving system and parameters for ease of use.

use std::path::Path;

use bellman::groth16::{Parameters, PreparedVerifyingKey};
use bls12_381::Bls12;
use ff::Field;
use rand_core::OsRng;
use zcash_primitives::{
    merkle_tree::MerklePath,
    sapling::{
        redjubjub::{PublicKey, Signature},
        Diversifier, Node, PaymentAddress, ProofGenerationKey, Rseed,
    },
    transaction::components::{Amount, GROTH_PROOF_SIZE},
};
use zcash_proofs::{default_params_folder, load_parameters, parse_parameters, ZcashParameters};

use crate::{
    errors::ProverError,
    prover::SaplingProvingContext,
    txbuilder::{OutputDescription, SpendDescription},
};

// Circuit names
const SAPLING_SPEND_NAME: &str = "sapling-spend.params";
const SAPLING_OUTPUT_NAME: &str = "sapling-output.params";

// Circuit hashes
const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
const SPROUT_HASH: &str = "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";

/// An implementation of [`HsmTxProver`] using Sapling Spend and Output
/// parameters from locally-accessible paths.
pub struct LocalTxProver {
    spend_params: Parameters<Bls12>,
    spend_vk: PreparedVerifyingKey<Bls12>,
    output_params: Parameters<Bls12>,
}

impl LocalTxProver {
    /// Creates a `LocalTxProver` using parameters from the given local paths.
    ///
    /// # Examples
    ///
    /// ```should_panic
    /// use std::path::Path;
    /// use ledger_zcash_chain_builder::LocalTxProver;
    ///
    /// let tx_prover = LocalTxProver::new(
    ///     Path::new("/path/to/sapling-spend.params"),
    ///     Path::new("/path/to/sapling-output.params"),
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the paths do not point to valid parameter
    /// files with the expected hashes.
    pub fn new(
        spend_path: &Path,
        output_path: &Path,
    ) -> Self {
        let ZcashParameters { spend_params, spend_vk, output_params, .. } =
            load_parameters(spend_path, output_path, None);
        LocalTxProver { spend_params, spend_vk, output_params }
    }

    /// Creates a `LocalTxProver` using parameters specified as byte arrays.
    ///
    /// # Examples
    ///
    /// ```should_panic
    /// use std::path::Path;
    /// use ledger_zcash_chain_builder::LocalTxProver;
    ///
    /// let tx_prover = LocalTxProver::from_bytes(&[0u8], &[0u8]);
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the byte arrays do not contain valid
    /// parameters with the expected hashes.
    pub fn from_bytes(
        spend_param_bytes: &[u8],
        output_param_bytes: &[u8],
    ) -> Self {
        let p = parse_parameters(spend_param_bytes, output_param_bytes, None);

        LocalTxProver { spend_params: p.spend_params, spend_vk: p.spend_vk, output_params: p.output_params }
    }

    /// Attempts to create a `LocalTxProver` using parameters from the default
    /// local location.
    ///
    /// Returns `None` if any of the parameters cannot be found in the default
    /// local location.
    ///
    /// # Examples
    ///
    /// ```
    /// use ledger_zcash_chain_builder::LocalTxProver;
    ///
    /// match LocalTxProver::with_default_location() {
    ///     Some(tx_prover) => (),
    ///     None => println!("Please run zcash-fetch-params or fetch-params.sh to download the parameters."),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the parameters in the default local location
    /// do not have the expected hashes.
    #[cfg(feature = "local-prover")]
    #[cfg_attr(docsrs, doc(cfg(feature = "local-prover")))]
    pub fn with_default_location() -> Option<Self> {
        let params_dir = default_params_folder()?;
        let (spend_path, output_path) = if params_dir.exists() {
            (params_dir.join(SAPLING_SPEND_NAME), params_dir.join(SAPLING_OUTPUT_NAME))
        } else {
            return None;
        };
        if !(spend_path.exists() && output_path.exists()) {
            return None;
        }

        Some(LocalTxProver::new(&spend_path, &output_path))
    }

    /// Creates a `LocalTxProver` using Sapling parameters bundled inside the
    /// binary.
    ///
    /// This requires the `bundled-prover` feature, which will increase the
    /// binary size by around 50 MiB.
    #[cfg(feature = "bundled-prover")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bundled-prover")))]
    pub fn bundled() -> Self {
        let (spend_buf, output_buf) = wagyu_zcash_parameters::load_sapling_parameters();
        let ZcashParameters { spend_params, spend_vk, output_params, .. } =
            parse_parameters(&spend_buf[..], &output_buf[..], None);

        LocalTxProver { spend_params, spend_vk, output_params }
    }
}

/// HSM compatible version of [`crate::zcash::primitives::prover::TxProver`]
pub trait HsmTxProver {
    /// Type for persisting any necessary context across multiple Sapling
    /// proofs.
    type SaplingProvingContext;

    type Error: std::error::Error;

    /// Instantiate a new Sapling proving context.
    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext;

    /// Create the value commitment, re-randomized key, and proof for a Sapling
    /// [`SpendDescription`], while accumulating its value commitment randomness
    /// inside the context for later use.
    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
        rcv: jubjub::Fr,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), Self::Error>;

    /// Create the value commitment and proof for a Sapling
    /// [`OutputDescription`], while accumulating its value commitment
    /// randomness inside the context for later use.
    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
        rcv: jubjub::Fr,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), Self::Error>;

    /// Create the `bindingSig` for a Sapling transaction.
    ///
    /// All calls to [`HsmTxProver::spend_proof`] and
    /// [`HsmTxProver::output_proof`] must be completed before calling this
    /// function.
    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        value_balance: Amount,
        sighash: &[u8; 32],
    ) -> Result<Signature, Self::Error>;
}

impl HsmTxProver for LocalTxProver {
    type SaplingProvingContext = SaplingProvingContext;
    type Error = ProverError;

    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
        SaplingProvingContext::new()
    }

    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
        rcv: jubjub::Fr,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ProverError> {
        let (proof, cv, rk) = ctx.spend_proof(
            proof_generation_key,
            diversifier,
            rseed,
            ar,
            value,
            anchor,
            merkle_path,
            &self.spend_params,
            &self.spend_vk,
            rcv,
        )?;

        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .map_err(|_| ProverError::ReadWriteError)?;

        Ok((zkproof, cv, rk))
    }

    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
        rcv: jubjub::Fr,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), ProverError> {
        let (proof, cv) = ctx.output_proof(esk, payment_address, rcm, value, &self.output_params, rcv)?;

        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .map_err(|_| ProverError::OutputProof)?;

        Ok((zkproof, cv))
    }

    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        value_balance: Amount,
        sighash: &[u8; 32],
    ) -> Result<Signature, ProverError> {
        ctx.binding_sig(value_balance, sighash)
    }
}

impl zcash_primitives::sapling::prover::TxProver for LocalTxProver {
    type SaplingProvingContext = <Self as HsmTxProver>::SaplingProvingContext;

    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
        HsmTxProver::new_sapling_proving_context(self)
    }

    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ()> {
        // default, same as zcash's prover
        let mut rng = OsRng;
        let rcv = jubjub::Fr::random(&mut rng);

        HsmTxProver::spend_proof(
            self,
            ctx,
            proof_generation_key,
            diversifier,
            rseed,
            ar,
            value,
            anchor,
            merkle_path,
            rcv,
        )
        .map_err(|_| ())
    }

    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
    ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
        // default, same as zcash's prover
        let mut rng = OsRng;
        let rcv = jubjub::Fr::random(&mut rng);

        HsmTxProver::output_proof(self, ctx, esk, payment_address, rcm, value, rcv).expect("output proof")
    }

    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        value_balance: Amount,
        sighash: &[u8; 32],
    ) -> Result<Signature, ()> {
        HsmTxProver::binding_sig(self, ctx, value_balance, sighash).map_err(|_| ())
    }
}
