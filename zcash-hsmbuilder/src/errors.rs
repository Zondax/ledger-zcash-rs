use std::error;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum Error {
    AnchorMismatch,
    BindingSig,
    ChangeIsNegative,
    InvalidAddress,
    InvalidAddressFormat,
    InvalidAddressHash,
    InvalidAmount,
    NoChangeAddress,
    SpendProof,
    MissingSpendSig,
    SpendSig,
    InvalidSpendSig,
    NoSpendSig,
    TranspararentSig,
    Finalization,
    MinShieldedOuputs,
    BuilderNoKeys,
    ReadWriteError,
    InvalidOVKHashSeed,
    AlreadyAuthorized,
    Unauthorized,
    UnknownAuthorization,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AnchorMismatch => {
                write!(f, "Anchor mismatch (anchors for all spends must be equal)")
            }
            Error::BindingSig => write!(f, "Failed to create bindingSig"),
            Error::ChangeIsNegative => write!(f, "Change is negative"),
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::NoChangeAddress => {
                write!(f, "No change address specified or discoverable")
            }
            Error::SpendProof => {
                write!(f, "Failed to create Sapling spend proof")
            }
            Error::MissingSpendSig => {
                write!(f, "Missing Sapling spend signature(s)")
            }
            Error::SpendSig => {
                write!(f, "Failed to get Sapling spend signature")
            }
            Error::InvalidSpendSig => {
                write!(f, "Sapling spend signature failed to verify")
            }
            Error::NoSpendSig => {
                write!(f, "No Sapling spend signatures")
            }
            Error::InvalidAddressFormat => {
                write!(f, "Incorrect format of address")
            }
            Error::InvalidAddressHash => write!(f, "Incorrect hash of address"),
            Error::TranspararentSig => {
                write!(f, "Failed to sign transparent inputs")
            }
            Error::Finalization => {
                write!(f, "Failed to build complete transaction")
            }
            Error::MinShieldedOuputs => {
                write!(f, "Not enough shielded outputs for transaction")
            }
            Error::BuilderNoKeys => {
                write!(f, "Builder does not have any keys set")
            }
            Error::ReadWriteError => {
                write!(f, "Error writing/reading bytes to/from vector")
            }
            Error::InvalidOVKHashSeed => {
                write!(f, "Error: either OVK or hashseed should be some")
            }
            Error::AlreadyAuthorized => {
                write!(f, "Error: operation not available after authorization")
            }
            Error::Unauthorized => {
                write!(f, "Error: operation not available without authorization")
            }
            Error::UnknownAuthorization => {
                write!(f, "Error: authorization status unknown")
            }
        }
    }
}

impl error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::ReadWriteError
    }
}
