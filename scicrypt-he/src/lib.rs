#![feature(generic_associated_types)]
// This is necessary for now, hopefully we can go back to stable around October

/// Partially homomorphic cryptosystems with one key.
pub mod cryptosystems;

/// Partially homomorphic threshold cryptosystems that require multiple parties to decrypt.
pub mod threshold_cryptosystems;

pub use scicrypt_traits;
