//! This module mostly contains data structures that are originally present in the
//! zcash_primitives crate but have been adapted to be HSM compatible

use std::io::{self, Write};

use crate::zcash::primitives::{
    consensus,
    keys::OutgoingViewingKey,
    legacy::{Script, TransparentAddress},
    memo::MemoBytes as Memo,
    merkle_tree::MerklePath,
    note_encryption::SaplingNoteEncryption,
    primitives::{Diversifier, Note, PaymentAddress, ProofGenerationKey, Rseed},
    sapling::Node,
    transaction::{
        components::{Amount, OutPoint, TxIn, TxOut, GROTH_PROOF_SIZE},
        signature_hash_data, SignableInput, TransactionData, SIGHASH_ALL,
    },
};
use crypto_api_chachapoly::ChachaPolyIetf;
use group::GroupEncoding;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{data::HashSeed, errors::Error, txprover::HsmTxProver};

const OUT_PLAINTEXT_SIZE: usize = 32 + // pk_d
    32; // esk
const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

#[derive(Clone)]
pub struct SpendDescriptionInfo {
    //extsk: ExtendedSpendingKey, //change this to path in ledger
    pub diversifier: Diversifier,
    pub note: Note,
    pub alpha: jubjub::Fr,
    //get both from ledger and generate self
    pub merkle_path: MerklePath<Node>,
    pub proofkey: ProofGenerationKey,
    //get from ledger
    pub rcv: jubjub::Fr,
}

#[derive(Clone)]
pub struct SaplingOutput {
    /// `None` represents the `ovk = ⊥` case.
    pub ovk: Option<OutgoingViewingKey>,
    //get from ledger
    pub to: PaymentAddress,
    pub note: Note,
    pub memo: Memo,
    pub rcv: jubjub::Fr, //get from ledger
    pub hashseed: Option<HashSeed>,
}

impl SaplingOutput {
    pub fn new<R: RngCore + CryptoRng, P: consensus::Parameters>(
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<Memo>,
        rcv: jubjub::Fr,
        rseed: Rseed,
        hashseed: Option<HashSeed>,
    ) -> Result<Self, Error> {
        let g_d = match to.g_d() {
            Some(g_d) => g_d,
            None => return Err(Error::InvalidAddress),
        };
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        //let rseed = generate_random_rseed::<P, R>(height, rng);

        let note = Note {
            g_d,
            pk_d: *to.pk_d(),
            value: value.into(),
            rseed,
        };

        Ok(SaplingOutput {
            ovk,
            to,
            note,
            memo: memo.unwrap_or_else(Memo::empty),
            rcv,
            hashseed,
        })
    }

    pub fn build<P: HsmTxProver, R: RngCore + CryptoRng>(
        self,
        prover: &P,
        ctx: &mut P::SaplingProvingContext,
        rng: &mut R,
    ) -> crate::zcash::primitives::transaction::components::OutputDescription {
        let mut encryptor = SaplingNoteEncryption::new(
            self.ovk,
            self.note.clone(),
            self.to.clone(),
            self.memo,
            rng,
        );

        let (zkproof, cv) = prover.output_proof(
            ctx,
            *encryptor.esk(),
            self.to,
            self.note.rcm(),
            self.note.value,
            self.rcv,
        );

        let cmu = self.note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let mut out_ciphertext;
        if self.ovk.is_some() {
            out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu);
        } else {
            let seed = self.hashseed.unwrap().0;
            let mut randbytes = [0u8; 32 + OUT_PLAINTEXT_SIZE];
            for i in 0..3 {
                let mut sha256 = Sha256::new();
                sha256.update([i as u8]);
                sha256.update(seed);
                let h = sha256.finalize();
                randbytes[i * 32..(i + 1) * 32].copy_from_slice(&h);
            }
            let mut ock = [0u8; 32];
            ock.copy_from_slice(&randbytes[0..32]);
            let mut input = [0u8; OUT_PLAINTEXT_SIZE];
            input.copy_from_slice(&randbytes[32..]);
            out_ciphertext = [0u8; OUT_CIPHERTEXT_SIZE];
            assert_eq!(
                ChachaPolyIetf::aead_cipher()
                    .seal_to(&mut out_ciphertext, &input, &[], ock.as_ref(), &[0u8; 12])
                    .unwrap(),
                OUT_CIPHERTEXT_SIZE
            );
        }

        let ephemeral_key = (*encryptor.epk()).into();

        crate::zcash::primitives::transaction::components::OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        }
    }
}

pub struct TransparentInputInfo {
    pub pubkey: secp256k1::PublicKey,
    pub coin: TxOut,
}

pub struct TransparentInputs {
    pub secp: secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    pub inputs: Vec<TransparentInputInfo>,
}

impl Default for TransparentInputs {
    fn default() -> Self {
        TransparentInputs {
            secp: secp256k1::Secp256k1::gen_new(),
            inputs: Default::default(),
        }
    }
}

impl TransparentInputs {
    pub fn push(
        &mut self,
        mtx: &mut TransactionData,
        pubkey: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        if coin.value.is_negative() {
            return Err(Error::InvalidAmount);
        }
        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKey(hash)) => {
                use ripemd160::Ripemd160;
                use sha2::{Digest, Sha256};
                if hash[..] != Ripemd160::digest(&Sha256::digest(&pubkey.serialize()))[..] {
                    return Err(Error::InvalidAddressHash);
                }
            }
            _ => return Err(Error::InvalidAddressFormat),
        }

        mtx.vin.push(TxIn::new(utxo));
        self.inputs.push(TransparentInputInfo { pubkey, coin });

        Ok(())
    }

    pub fn value_sum(&self) -> Amount {
        {
            self.inputs
                .iter()
                .map(|input| input.coin.value)
                .sum::<Amount>()
        }
    }

    pub fn apply_signatures(
        &self,
        signatures: Vec<secp256k1::Signature>,
        mtx: &mut TransactionData,
        consensus_branch_id: consensus::BranchId,
    ) -> Result<(), Error> {
        if signatures.len() != self.inputs.len() {
            return Err(Error::TranspararentSig);
        }
        let mut sighash = [0u8; 32];

        for (i, info) in self.inputs.iter().enumerate() {
            sighash.copy_from_slice(&signature_hash_data(
                mtx,
                consensus_branch_id,
                SIGHASH_ALL,
                SignableInput::transparent(i, &info.coin.script_pubkey, info.coin.value),
            ));

            let msg = secp256k1::Message::from_slice(&sighash).expect("32 bytes");
            let sig = signatures[i];
            let pk = info.pubkey;
            if self.secp.verify(&msg, &sig, &pk).is_err() {
                return Err(Error::TranspararentSig);
            }
            // Signature has to have "SIGHASH_ALL" appended to it
            let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
            sig_bytes.extend(&[SIGHASH_ALL as u8]);

            // P2PKH scriptSig
            mtx.vin[i].script_sig =
                Script::default() << &sig_bytes[..] << &info.pubkey.serialize()[..];
        }
        Ok(())
    }
}

/// Metadata about a transaction created by a [`crate::Builder`].
#[derive(Debug, PartialEq, Clone, Default)]
pub struct TransactionMetadata {
    pub(crate) spend_indices: Vec<usize>,
    pub(crate) output_indices: Vec<usize>,
}

impl TransactionMetadata {
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the index within the transaction of the [`SpendDescription`] corresponding
    /// to the `n`-th call to [`crate::Builder::add_sapling_spend`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first spend
    /// they added (via the first call to [`crate::Builder::add_sapling_spend`]) is the first
    /// [`SpendDescription`] in the transaction.
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`crate::Builder::add_sapling_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`crate::Builder::add_sapling_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
}

#[derive(Clone)]
pub struct NullifierInput {
    pub rcm_old: [u8; 32],
    pub notepos: [u8; 8],
}

impl NullifierInput {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.rcm_old)?;
        writer.write_all(&self.notepos)
    }
}

#[derive(Clone)]
pub struct TransparentScriptData {
    pub prevout: [u8; 36],
    pub script_pubkey: [u8; 26],
    pub value: [u8; 8],
    pub sequence: [u8; 4],
}

impl TransparentScriptData {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.prevout)?;
        writer.write_all(&self.script_pubkey)?;
        writer.write_all(&self.value)?;
        writer.write_all(&self.sequence)
    }
}

#[derive(Clone)]
pub struct SpendDescription {
    pub cv: [u8; 32],
    pub anchor: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

impl SpendDescription {
    pub fn from(
        info: &crate::zcash::primitives::transaction::components::SpendDescription,
    ) -> SpendDescription {
        SpendDescription {
            cv: info.cv.to_bytes(),
            anchor: info.anchor.to_bytes(),
            nullifier: info.nullifier.0,
            rk: info.rk.0.to_bytes(),
            zkproof: info.zkproof,
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.anchor)?;
        writer.write_all(&self.nullifier)?;
        writer.write_all(&self.rk)?;
        writer.write_all(&self.zkproof)
    }
}

#[derive(Clone)]
pub struct OutputDescription {
    pub cv: [u8; 32],
    pub cmu: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

impl From<&crate::zcash::primitives::transaction::components::OutputDescription>
    for OutputDescription
{
    fn from(from: &crate::zcash::primitives::transaction::components::OutputDescription) -> Self {
        Self {
            cv: from.cv.to_bytes(),
            cmu: from.cmu.to_bytes(),
            ephemeral_key: from.ephemeral_key.to_bytes(),
            enc_ciphertext: from.enc_ciphertext,
            out_ciphertext: from.out_ciphertext,
            zkproof: from.zkproof,
        }
    }
}

impl OutputDescription {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.cmu)?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }
}

/// Converts a zcash_primitives' SpendDescription to the HSM-compatible format
pub fn spend_data_hms_fromtx(
    input: &[crate::zcash::primitives::transaction::components::SpendDescription],
) -> Vec<SpendDescription> {
    let mut data = Vec::new();
    for info in input.iter() {
        let description = SpendDescription::from(info);
        data.push(description);
    }
    data
}

/// Converts a zcash_primitives' OutputDescription to the HSM-compatible format
pub fn output_data_hsm_fromtx(
    input: &[crate::zcash::primitives::transaction::components::OutputDescription],
) -> Vec<OutputDescription> {
    let mut data = Vec::new();
    for info in input.iter() {
        let description = OutputDescription::from(info);
        data.push(description);
    }
    data
}

/// Converts a list of [`SpendDescriptionInfo`] to a vec of [`NullifierInput`]s
pub fn spend_old_data_fromtx(data: &[SpendDescriptionInfo]) -> Vec<NullifierInput> {
    let mut v = Vec::new();
    for info in data.iter() {
        let n = NullifierInput {
            rcm_old: info.note.rcm().to_bytes(),
            notepos: info.merkle_path.position.to_le_bytes(),
        };
        v.push(n);
    }
    v
}

/// Generates a list of [`TransparentScriptData`] from
/// a list of [`TransparentInputInfo`] and `TransactionData`
pub fn transparent_script_data_fromtx(
    tx: &TransactionData,
    inputs: &[TransparentInputInfo],
) -> Result<Vec<TransparentScriptData>, Error> {
    let mut data = Vec::new();
    for (i, info) in inputs.iter().enumerate() {
        let mut prevout = [0u8; 36];
        prevout[0..32].copy_from_slice(tx.vin[i].prevout.hash().as_ref());
        prevout[32..36].copy_from_slice(&tx.vin[i].prevout.n().to_le_bytes());

        let mut script_pubkey = [0u8; 26];
        info.coin.script_pubkey.write(&mut script_pubkey[..])?;

        let mut value = [0u8; 8];
        value.copy_from_slice(&info.coin.value.to_i64_le_bytes());

        let mut sequence = [0u8; 4];
        sequence.copy_from_slice(&tx.vin[i].sequence.to_le_bytes());

        let ts = TransparentScriptData {
            prevout,
            script_pubkey,
            value,
            sequence,
        };
        data.push(ts);
    }
    Ok(data)
}
