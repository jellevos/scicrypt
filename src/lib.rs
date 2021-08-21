#![doc = include_str!("../README.md")]
#![warn(missing_docs, unused_imports)]

/// Functions for generating random prime numbers.
pub mod number_theory;

/// Random number generation that is consistent with the dependencies' requirements.
pub mod randomness;

/// Partially homomorphic cryptosystems with one key.
pub mod cryptosystems;

/// Partially homomorphic threshold cryptosystems that require multiple parties to decrypt.
pub mod threshold_cryptosystems;

/// Rich representation of a ciphertext that associates it with the corresponding public key.
/// This allows for performing homomorphic operations using operator overloading, among others.
pub struct RichCiphertext<'pk, C, PK> {
    ciphertext: C,
    public_key: &'pk PK,
}

/// Functionality to easily turn a ciphertext into a rich ciphertext
pub trait Enrichable<PK> {
    /// Enriches a ciphertext by associating it with a corresponding public key.
    fn enrich(self, public_key: &PK) -> RichCiphertext<Self, PK>
    where
        Self: Sized,
    {
        RichCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

/// General error that arises when decryption fails, for example because there were not enough
/// distinct decryption shares to decrypt a threshold ciphertext.
#[derive(Debug)]
pub struct DecryptionError;
