/*******************************************************************************
*   (c) 2018-2022 Zondax AG
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

use std::marker::PhantomData;

use zcash_primitives::transaction::{
    self,
    components::{
        sapling::Authorization as SAuthorization, transparent::Authorization as TAuthorization, GROTH_PROOF_SIZE,
    },
    Authorization, Authorized,
};

pub type Unauthorized = MixedAuthorization<transparent::Unauthorized, sapling::Unauthorized>;

/// Encodes a mixed [`Authorization`] state
pub struct MixedAuthorization<T: TAuthorization, S: SAuthorization> {
    transparent: T,
    sapling: S,
}

impl<T: TAuthorization, S: SAuthorization> Authorization for MixedAuthorization<T, S> {
    type TransparentAuth = T;
    type SaplingAuth = S;
    type OrchardAuth = <transaction::Unauthorized as Authorization>::OrchardAuth;

    #[cfg(feature = "zfuture")]
    type TzeAuth = <transaction::Unauthorized as Authorization>::TzeAuth;
}

pub mod sapling {
    use zcash_primitives::transaction::components::sapling;

    use crate::txbuilder::SpendDescriptionInfo;

    /// Unauthorized Sapling bundle - Similar to v0.5
    ///
    /// This is a slight variation on [`sapling::builder::Unauthorized`]
    /// where the associated AuthSig is not a private struct and has
    /// some necessary fields added.
    ///
    /// This allows the [`sapling::SpendDescription`] to actually be
    /// instantiated
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Unauthorized {}

    impl sapling::Authorization for Unauthorized {
        type Proof = <sapling::builder::Unauthorized as sapling::Authorization>::Proof;

        type AuthSig = SpendDescriptionInfo;
    }
}

pub mod transparent {
    use zcash_primitives::transaction::{self, components::transparent, TransactionData};

    use crate::{errors::Error, txbuilder::TransparentInputInfo};

    /// Unauthorized Transparent bundle - Similar to v0.5
    ///
    /// This is a slight variation on [`transparent::builder::Unauthorized`]
    /// where the authorization is not a private struct, thus can be constructed
    /// manually
    #[derive(Debug, Clone)]
    pub struct Unauthorized {
        pub secp: secp256k1::Secp256k1<secp256k1::VerifyOnly>,
        pub inputs: Vec<TransparentInputInfo>,
    }

    impl Default for Unauthorized {
        fn default() -> Self {
            Self { secp: secp256k1::Secp256k1::gen_new(), inputs: vec![] }
        }
    }

    impl transparent::Authorization for Unauthorized {
        type ScriptSig = <transparent::builder::Unauthorized as transparent::Authorization>::ScriptSig;
    }

    impl transaction::sighash::TransparentAuthorizingContext for Unauthorized {
        fn input_amounts(&self) -> Vec<transaction::components::Amount> {
            self.inputs
                .iter()
                .map(|input| input.coin.value)
                .collect()
        }

        fn input_scriptpubkeys(&self) -> Vec<zcash_primitives::legacy::Script> {
            self.inputs
                .iter()
                .map(|input| input.coin.script_pubkey.clone())
                .collect()
        }
    }
}
