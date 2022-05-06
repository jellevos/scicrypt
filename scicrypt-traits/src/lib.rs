#![feature(trait_alias)]
// These features are necessary to prevent the operator overloading for AssociatedCiphertext to clash between additive and multiplicative,
// so we restrict the AssociatedCiphertext to never be a plaintext.
#![feature(auto_traits, negative_impls)]
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

/// General notion of secret sharing
pub mod secret_sharing;

/// General error that arises when decryption fails, for example because there were not enough
/// distinct decryption shares to decrypt a threshold ciphertext.
#[derive(Debug)]
pub struct DecryptionError;

/// Homomorphic properties of homomorphic encryption schemes
pub mod homomorphic;
