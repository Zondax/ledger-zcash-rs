use std::convert::TryFrom;

use crate::zcash::primitives::{
    consensus::{self, Parameters},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    sapling::{Diversifier, Node, Note, PaymentAddress},
    transaction::{
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
};
use zcash_hsmbuilder::{txbuilder::SaplingMetadata, txprover::HsmTxProver};

use arrayvec::ArrayVec;
use rand_core::{CryptoRng, RngCore};
use tokio::sync::mpsc;
use zx_bip44::BIP44Path;

use crate::{
    DataInput, DataShieldedOutput, DataShieldedSpend, DataTransparentInput, DataTransparentOutput,
    ZcashApp,
};

/// Represents the possible tx fee values
#[derive(Clone, Copy, Debug)]
pub enum TxFee {
    /// 1000
    Thousand,
    /// 10'000
    TenThousand,
}

impl From<TxFee> for u64 {
    fn from(fee: TxFee) -> Self {
        match fee {
            TxFee::Thousand => 1000,
            TxFee::TenThousand => 10_000,
        }
    }
}

impl TryFrom<usize> for TxFee {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            _ if value <= 1000 => Ok(Self::Thousand),
            _ if value <= 10_000 => Ok(Self::TenThousand),
            _ => Err(()),
        }
    }
}

impl TryFrom<u64> for TxFee {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            _ if value <= 1000 => Ok(Self::Thousand),
            _ if value <= 10_000 => Ok(Self::TenThousand),
            _ => Err(()),
        }
    }
}

/// Ergonomic ZCash transaction builder for HSM
#[derive(Default)]
pub struct Builder {
    transparent_inputs: ArrayVec<DataTransparentInput, 5>,
    transaprent_outputs: ArrayVec<DataTransparentOutput, 5>,
    sapling_spends: ArrayVec<DataShieldedSpend, 5>,
    sapling_outputs: ArrayVec<DataShieldedOutput, 5>,
    change_address: Option<(OutgoingViewingKey, PaymentAddress)>,
}

impl TryFrom<DataInput> for Builder {
    type Error = BuilderError;

    fn try_from(input: DataInput) -> Result<Self, Self::Error> {
        let mut builder = Self::default();

        for ti in input.vec_tin.into_iter() {
            builder.add_transparent_input(
                ti.path,
                ti.pk,
                ti.prevout,
                TxOut {
                    value: ti.value,
                    script_pubkey: ti.script,
                },
            )?;
        }

        for to in input.vec_tout.into_iter() {
            builder.add_transparent_output(
                &to.script_pubkey
                    .address()
                    .ok_or(BuilderError::InvalidAddress)?,
                to.value,
            )?;
        }

        for zi in input.vec_sspend.into_iter() {
            builder.add_sapling_spend(zi.path, zi.diversifier, zi.note, zi.witness)?;
        }

        for zo in input.vec_soutput.into_iter() {
            builder.add_sapling_output(zo.ovk, zo.address, zo.value, zo.memo)?;
        }

        Ok(builder)
    }
}

/// All the possible errors returned by the builder
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// The specified fee is invalid
    ///
    /// It's likely that the fee is higher than the supported amount by Ledger
    #[error("invalid fee")]
    InvalidFee,

    /// Attempted to add too many elements to the transaction
    ///
    /// This is a limitation of the ledger, where currently maximum 5 elements are accepted per type
    #[error("too many elements")]
    TooManyElements,

    /// Error occured with initializing tx with ledger
    #[error("tx initialization failed")]
    UnableToInitializeTx,

    /// Invalid note amount, most likely negative or more than maximum allowed
    #[error("invalid amount")]
    InvalidAmount,

    /// Script address of UTXO was not a public key
    #[error("invalid utxo address")]
    InvalidUTXOAddress,

    /// Attempted to add spends with separate Merkle tree roots
    #[error("sapling sends with different merkle roots")]
    AnchorMismatch,

    /// Error occured when retrieving sapling spend data from ledger
    #[error("error communicating with ledger during sapling spend retrieval")]
    UnableToRetrieveSpendInfo(usize),
    /// Error occured when retrieving transparent output data from ledger
    #[error("error communicating with ledger during transparent output retrieval")]
    UnableToRetrieveOutputInfo(usize),

    /// Error occured while checking validity of spend
    #[error("bad combination of OVK and hash-seed")]
    InvalidOVKHashSeed(usize),

    /// Error occured when building tx for ledger
    #[error("error communicating with ledger during transaction building")]
    FailedToBuildTx,

    /// Error occured when signing tx with ledger
    #[error("error communicating with ledger during transaction signing")]
    FailedToSignTx,

    /// Attempted to add sapling output with invalid g_d
    #[error("invalid sapling payment address")]
    InvalidAddress,

    /// Failed to retrieve transparent signature
    #[error("error communicating with ledger during transparent signature retrieval")]
    UnableToRetrieveTransparentSig(usize),
    /// Failed to retrieve sapling signature
    #[error("error communicating with ledger during sapling signature retrieval")]
    UnableToRetrieveSaplingSig(usize),

    /// Error occured when applying obtained transparent signatures
    #[error("failed to apply transparent signatures")]
    UnableToApplyTransparentSigs,
    /// Error occured when applying obtained sapling signatures
    #[error("failed to apply sapling signatures")]
    UnableToApplySaplingSigs,

    /// Error occured during finalization
    #[error("failed to finalize transaction")]
    FinalizationError,
}

impl Builder {
    /// Instantiate a new [`Builder`]
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a new transparent input to the transaction
    ///
    /// Performs checks to ensure the input is valid
    pub fn add_transparent_input(
        &mut self,
        path: BIP44Path,
        key: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<&mut Self, BuilderError> {
        if coin.value.is_negative() {
            return Err(BuilderError::InvalidAmount);
        }

        let pkh = {
            use ripemd::{Digest as _, Ripemd160};
            use sha2::{Digest as _, Sha256};

            let serialized = key.serialize();
            let sha = Sha256::digest(&serialized);

            let mut ripemd = Ripemd160::new();
            ripemd.update(&sha[..]);
            ripemd.finalize()
        };

        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKey(hash)) if hash == pkh[..] => {}
            _ => return Err(BuilderError::InvalidUTXOAddress),
        }

        self.transparent_inputs
            .try_push(DataTransparentInput {
                path,
                pk: key,
                prevout: utxo,
                script: coin.script_pubkey,
                value: coin.value,
            })
            .map_err(|_| BuilderError::TooManyElements)?;

        Ok(self)
    }

    /// Add a new transparent output to the transaction
    ///
    /// Performs necessary checks to ensure the transparent output is valid
    pub fn add_transparent_output(
        &mut self,
        to: &TransparentAddress,
        value: Amount,
    ) -> Result<&mut Self, BuilderError> {
        if value.is_negative() {
            return Err(BuilderError::InvalidAmount);
        }

        self.transaprent_outputs
            .try_push(DataTransparentOutput {
                value,
                script_pubkey: to.script(),
            })
            .map_err(|_| BuilderError::TooManyElements)?;

        Ok(self)
    }

    /// Add a new sapling spend to the transaction
    ///
    /// Performs some checks to ensure as much as possible that the spend is valid
    pub fn add_sapling_spend(
        &mut self,
        path: u32,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<&mut Self, BuilderError> {
        //just need to check against the first one (if it exists)
        // as all will be checked against it to all are equal
        if let Some(spend) = self.sapling_spends.first() {
            let spend_cmu = Node::new(spend.note.cmu().into());
            let spend_root = spend.witness.root(spend_cmu);

            let cmu = Node::new(note.cmu().into());
            let this_root = merkle_path.root(cmu);

            if this_root != spend_root {
                return Err(BuilderError::AnchorMismatch);
            }
        }

        if Amount::from_u64(note.value).is_err() {
            return Err(BuilderError::InvalidAmount);
        }

        self.sapling_spends
            .try_push(DataShieldedSpend {
                path,
                note,
                diversifier,
                witness: merkle_path,
            })
            .map_err(|_| BuilderError::TooManyElements)?;

        Ok(self)
    }

    /// Add a new sapling output to the transaction
    ///
    /// Not all checks are done here, only those that are possible with the current information
    pub fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<&mut Self, BuilderError> {
        if to.g_d().is_none() {
            return Err(BuilderError::InvalidAddress);
        }

        if value.is_negative() {
            return Err(BuilderError::InvalidAmount);
        }

        self.sapling_outputs
            .try_push(DataShieldedOutput {
                address: to,
                value,
                ovk,
                memo,
            })
            .map_err(|_| BuilderError::TooManyElements)?;

        Ok(self)
    }

    /// If there are any shielded inputs, always have at least two shielded outputs,
    /// padding with dummy outputs if necessary.
    /// See <https://github.com/zcash/zcash/issues/3615>
    fn pad_sapling_outputs<R: RngCore>(&mut self, rng: &mut R) -> Result<&mut Self, BuilderError> {
        let dummies = 2usize.saturating_sub(self.sapling_outputs.len());

        for _ in 0..dummies {
            self.add_sapling_output(
                None,
                random_payment_address(rng),
                Amount::from_u64(0).unwrap(),
                None,
            )?;
        }
        Ok(self)
    }

    /// Sets the Sapling address to which any change will be sent.
    ///
    /// By default, change is sent to the Sapling address corresponding to the first note
    /// being spent (i.e. the first call to [`Builder::add_sapling_spend`]).
    pub fn send_change_to(&mut self, ovk: OutgoingViewingKey, to: PaymentAddress) {
        self.change_address = Some((ovk, to))
    }
}

impl Builder {
    fn into_data_input(self, fee: TxFee) -> DataInput {
        DataInput {
            txfee: fee.into(),
            vec_tin: self.transparent_inputs.into_iter().collect(),
            vec_tout: self.transaprent_outputs.into_iter().collect(),
            vec_sspend: self.sapling_spends.into_iter().collect(),
            vec_soutput: self.sapling_outputs.into_iter().collect(),
        }
    }

    /// Build the transaction, communicating with the ledger when necessary
    ///
    /// `height` is the target block height for inclusion on chain
    ///
    /// `branch` must be valid for the block height that this transaction is
    /// targeting. An invalid `consensus_branch_id` will *not* result in an error from
    /// this function, and instead will generate a transaction that will be rejected by
    /// the network.
    #[allow(clippy::too_many_arguments)]
    pub async fn build<P, E, TX, R>(
        mut self,
        app: &ZcashApp<E>,
        params: P,
        prover: &TX,
        fee: u64,
        rng: &mut R,
        height: u32,
        branch: consensus::BranchId,
        progress_notifier: Option<mpsc::Sender<usize>>,
    ) -> Result<(Transaction, SaplingMetadata), BuilderError>
    where
        R: RngCore + CryptoRng,
        TX: HsmTxProver + Send + Sync,
        P: Parameters + Send + Sync,
        E: ledger_transport::Exchange + Send + Sync,
        E::Error: std::error::Error,
    {
        let fee = TxFee::try_from(fee).map_err(|_| BuilderError::InvalidFee)?;
        self.pad_sapling_outputs(rng)?;

        let mut hsmbuilder =
            zcash_hsmbuilder::txbuilder::Builder::new_with_fee_rng(params, height, rng, fee.into());

        let input = self.into_data_input(fee);
        app.init_tx(input.to_inittx_data())
            .await
            .map_err(|_| BuilderError::UnableToInitializeTx)?;

        let DataInput {
            txfee: _,
            vec_tin,
            vec_tout,
            vec_sspend,
            vec_soutput,
        } = input;

        let num_transparent_inputs = vec_tin.len();
        let num_sapling_spends = vec_sspend.len();

        /* Feed the builder with the various parts,
         * retrieving data from the ledger device */
        for info in vec_tin.into_iter() {
            hsmbuilder
                .add_transparent_input(
                    info.pk,
                    info.prevout,
                    TxOut {
                        value: info.value,
                        script_pubkey: info.script,
                    },
                )
                //verified the inputs when we added it
                .unwrap();
        }

        for info in vec_tout.into_iter() {
            hsmbuilder
                .add_transparent_output(info.script_pubkey, info.value)
                //checked when we added these to the builder
                .unwrap();
        }

        for (i, info) in vec_sspend.into_iter().enumerate() {
            let (proofkey, rcv, alpha) = app
                .get_spendinfo()
                .await
                .map_err(|_| BuilderError::UnableToRetrieveSpendInfo(i))?;

            hsmbuilder
                .add_sapling_spend(
                    info.diversifier,
                    info.note,
                    info.witness,
                    alpha,
                    proofkey,
                    rcv,
                )
                //parameters checked before
                .unwrap();
        }

        for (i, info) in vec_soutput.into_iter().enumerate() {
            let (rcv, rseed, hash_seed) = app
                .get_outputinfo()
                .await
                .map_err(|_| BuilderError::UnableToRetrieveOutputInfo(i))?;

            if info.ovk.is_none() && hash_seed.is_none() {
                return Err(BuilderError::InvalidOVKHashSeed(i));
            }

            hsmbuilder
                .add_sapling_output(
                    info.ovk,
                    info.address,
                    info.value,
                    info.memo,
                    rcv,
                    rseed,
                    hash_seed,
                )
                //parameters checked before
                .unwrap();
        }

        // building finished, time to have the ledger sign everything
        let ledger_data = hsmbuilder
            .build_with_progress_notifier(branch, prover, progress_notifier)
            .map_err(|_| BuilderError::FailedToBuildTx)?;

        let _signed_hash = app
            .checkandsign(ledger_data)
            .await
            .map_err(|_| BuilderError::FailedToSignTx)?;

        let mut tsigs = Vec::with_capacity(num_transparent_inputs);
        let mut zsigs = Vec::with_capacity(num_sapling_spends);

        //retrieve signatures
        for i in 0..num_transparent_inputs {
            let sig = app
                .get_transparent_signature()
                .await
                .map_err(|_| BuilderError::UnableToRetrieveTransparentSig(i))?;
            tsigs.push(sig);
        }

        for i in 0..num_sapling_spends {
            let sig = app
                .get_spend_signature()
                .await
                .map_err(|_| BuilderError::UnableToRetrieveSaplingSig(i))?;
            zsigs.push(sig);
        }

        //apply them in the builder
        let hsmbuilder = hsmbuilder
            .add_signatures_spend(zsigs)
            .map_err(|_| BuilderError::UnableToApplySaplingSigs)?;
        let hsmbuilder = hsmbuilder
            .add_signatures_transparent(tsigs)
            .map_err(|_| BuilderError::UnableToApplyTransparentSigs)?;
        hsmbuilder
            .finalize()
            .map_err(|_| BuilderError::FinalizationError)
    }
}

fn random_payment_address<R: RngCore>(rng: &mut R) -> PaymentAddress {
    use ff::Field;

    let (diversifier, g_d) = loop {
        let mut d = [0; 11];
        rng.fill_bytes(&mut d);
        let diversifier = Diversifier(d);

        if let Some(g_d) = diversifier.g_d() {
            break (diversifier, g_d);
        }
    };

    loop {
        let dummy_ivk = jubjub::Fr::random(&mut *rng);
        let pk_d = g_d * dummy_ivk;
        if let Some(addr) = PaymentAddress::from_parts(diversifier, pk_d) {
            break addr;
        }
    }
}
