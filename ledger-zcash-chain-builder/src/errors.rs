use bellman::VerificationError;
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
use thiserror::Error as ThisError;

#[derive(ThisError, Debug, PartialEq)]
pub enum Error {
    #[error("Anchor mismatch (anchors for all spends must be equal)")]
    AnchorMismatch,
    #[error("Failed to create bindingSig")]
    BindingSig,
    #[error("Change is negative")]
    ChangeIsNegative,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Incorrect format of address")]
    InvalidAddressFormat,
    #[error("Incorrect hash of address")]
    InvalidAddressHash,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("No change address specified or discoverable")]
    NoChangeAddress,
    #[error("Failed to create Sapling spend proof")]
    SpendProof,
    #[error("Missing Sapling spend signature(s)")]
    MissingSpendSig,
    #[error("Failed to get Sapling spend signature")]
    SpendSig,
    #[error("Sapling spend signature failed to verify")]
    InvalidSpendSig,
    #[error("No Sapling spend signatures")]
    NoSpendSig,
    #[error("Failed to sign transparent inputs")]
    TransparentSig,
    #[error("Failed to build complete transaction")]
    Finalization,
    #[error("Not enough shielded outputs for transaction")]
    MinShieldedOutputs,
    #[error("Builder does not have any keys set")]
    BuilderNoKeys,
    #[error("Error writing/reading bytes to/from vector")]
    #[from(std::io::Error)]
    ReadWriteError,
    #[error("Error: either OVK or hash_seed should be some")]
    InvalidOVKHashSeed,
    #[error("Error: operation not available after authorization")]
    AlreadyAuthorized,
    #[error("Error: operation not available without authorization")]
    Unauthorized,
    #[error("Error: authorization status unknown")]
    UnknownAuthorization,
}

#[derive(ThisError, Debug)]
pub enum ProverError {
    #[error("Failed to generate spend proof")]
    SpendProof,
    #[error("Failed to generate output proof")]
    OutputProof,
    #[error("Failed to generate binding signature")]
    BindingSig,
    #[error("Invalid Diversifier")]
    InvalidDiversifier,
    #[error("Synthesis error {:?}", .0)]
    #[from(bellman::SynthesisError)]
    Synthesis(bellman::SynthesisError),
    #[error("Verification error {:?}", .0)]
    #[from(VerificationError)]
    Verification(VerificationError),
    #[error("Invalid balance")]
    InvalidBalance, // Add more specific error variants as needed
    #[error("Error writing/reading bytes to/from vector")]
    #[from(std::io::Error)]
    ReadWriteError,
}
