#![feature(generic_associated_types)]
// This is necessary for now, hopefully we can go back to stable around October
#![warn(missing_docs, unused_imports)]

//! _This is a part of **scicrypt**. For more information, head to the
//! [scicrypt](https://crates.io/crates/scicrypt) crate homepage._
//!
//! General traits for cryptographic primitives in multi-party computation, such as homomorphic
//! (threshold) cryptosystems, oblivious transfers (WIP), secret sharing, etc.

/// Random number generation that is consistent with the dependencies' requirements.
pub mod randomness;

/// Concepts expressing the security level or setting of a given primitive or protocol.
pub mod security;

/// General notion of a cryptosystem
pub mod cryptosystems;

/// General notion of threshold cryptosystems
pub mod threshold_cryptosystems;

pub mod secret_sharing;

/// Functionality to easily turn a ciphertext into a rich ciphertext
pub trait Enrichable<'pk, PK, RC> {
    /// Enriches a ciphertext by associating it with a corresponding public key.
    fn enrich(self, public_key: &'pk PK) -> RC
    where
        Self: Sized;
}

/// General error that arises when decryption fails, for example because there were not enough
/// distinct decryption shares to decrypt a threshold ciphertext.
#[derive(Debug)]
pub struct DecryptionError;
