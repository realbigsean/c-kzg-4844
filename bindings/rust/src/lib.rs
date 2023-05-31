mod bindings;

macro_rules! banana {
    ($mod_name:ident) => {
        // Expose relevant types with idiomatic names.
        pub mod $mod_name {
            pub use super::bindings::$mod_name::{
                KZGCommitment as KzgCommitment, KZGProof as KzgProof, KZGSettings as KzgSettings,
                C_KZG_RET as CkzgError,
            };
            // Expose the constants.
            pub use super::bindings::$mod_name::{
                BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_G1_POINT,
                BYTES_PER_G2_POINT, BYTES_PER_PROOF, FIELD_ELEMENTS_PER_BLOB,
            };
            // Expose the remaining relevant types.
            pub use super::bindings::$mod_name::{Blob, Bytes32, Bytes48, Error};
        }
    };
}

banana!(minimal);
banana!(mainnet);
