#![feature(generic_associated_types)]
// This is necessary for now, hopefully we can go back to stable around October
#![warn(missing_docs, unused_imports)]

//! _This is a part of **scicrypt**. For more information, head to the
//! [scicrypt](https://crates.io/crates/scicrypt) crate homepage._
//!
//! This crate implements several well-known partially homomorphic cryptosystems, including
//! Paillier, ElGamal and RSA. We also implement several threshold versions of the cryptosystems,
//! where multiple keys must be used to successfully decrypt a ciphertext.

/// Partially homomorphic cryptosystems with one key.
pub mod cryptosystems;

/// Partially homomorphic threshold cryptosystems that require multiple parties to decrypt.
pub mod threshold_cryptosystems;

pub use scicrypt_traits;
