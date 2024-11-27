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
//! Wrapper over zcash crates and zecwallet fork of the crates
//!
//! Use this instead of importing things from zcash crates directly!!

#[allow(dead_code)]
// actually used in `DataShieldedOutput` debug implementation
/// The payment_address_bytes_fmt function formats the bytes of the payment
/// address for debug information
pub fn payment_address_bytes_fmt(
    this: &zcash_primitives::sapling::PaymentAddress,
    f: &mut std::fmt::Formatter,
) -> std::fmt::Result {
    let bytes = this.to_bytes();

    f.debug_tuple("PaymentAddress")
        .field(&bytes)
        .finish()
}
