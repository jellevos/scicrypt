#![feature(generic_associated_types)]
// This is necessary for now, hopefully we can go back to stable around October

/// Random number generation that is consistent with the dependencies' requirements.
pub mod randomness;

pub mod security;

pub mod cryptosystems;
pub mod threshold_cryptosystems;

/// Functionality to easily turn a ciphertext into a rich ciphertext
pub trait Enrichable<'pk, PK, RC> {
    /// Enriches a ciphertext by associating it with a corresponding public key.
    fn enrich(self, public_key: &'pk PK) -> RC where Self: Sized;
}

/// General error that arises when decryption fails, for example because there were not enough
/// distinct decryption shares to decrypt a threshold ciphertext.
#[derive(Debug)]
pub struct DecryptionError;
