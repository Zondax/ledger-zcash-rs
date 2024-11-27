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
//! This module provides a support library for Zcash applications on Ledger Nano S and X devices.
//! It includes functionality to handle APDU commands and errors, and to interact with the Zcash blockchain.

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

/// Re-export APDU-related types from the `ledger_transport` crate.
pub use ledger_transport::{APDUAnswer, APDUCommand, APDUErrorCode};
/// Re-export error handling utilities from the `ledger_zondax_generic` crate.
pub use ledger_zondax_generic::LedgerAppError;

/// Module containing the main functionality of the Ledger app.
mod app;
/// Re-export everything from the `app` module.
pub use app::*;

/// Module for Zcash-specific functionality.
pub mod zcash;

/// Module providing an ergonomic interface for building transactions.
#[path = "./txbuilder.rs"]
pub mod builder;

/// Module containing configuration constants for the application.
pub mod config;
