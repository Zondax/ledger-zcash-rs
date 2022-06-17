//! Wrapper over zcash crates and zecwallet fork of the crates
//!
//! Use this instead of importing things from zcash crates directly!!

cfg_if::cfg_if! {
    if #[cfg(all(feature = "zecwallet-compat", feature = "normal-zcash"))] {
        compile_error!("Only one feature should be enabled between 'zecwallet-compat' and 'normal-zcash'!");
    } else if #[cfg(feature = "zecwallet-compat")] {
        pub use zecw_primitives as primitives;
        pub use zecw_proofs as proofs;
    } else if #[cfg(feature = "normal-zcash")] {
        pub use zcash_primitives as primitives;
        pub use zcash_proofs as proofs;
    } else {
        compile_error!("One feature should be enabled between 'zecwallet-compat' and 'normal-zcash'!");
    }
}
