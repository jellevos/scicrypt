//! Lightweight cryptographic building blocks for proof of concept implementations in applied
//! cryptography.
//!
//! While many libraries implementing cryptographic building blocks exist, many fall in one of two
//! categories:
//! - Fast but rigid [like many written in C++]
//! - Slow but flexible [like many written in python]
//!
//! This library attempts to find a balance between speed and flexibility, to ease the process of
//! implementing proof of concepts of cryptographic protocols, such as those in the field of multi-
//! party computation (MPC).
//!
//! # Upcoming features
//! These are the upcoming minor versions and the functionality they will add.
//!
//! ## Version 0.2.0
//! _Threshold homomorphic cryptosystems update_
//! <table>
//!     <tr><td><b>Functionality</b></td><td><b>Done</b></td></tr>
//!     <tr><td>Threshold Paillier</td><td> </td></tr>
//!     <tr><td>Threshold ElGamal</td><td> </td></tr>
//! </table>
//!
//! ## Version 0.1.0
//! _Homomorphic cryptosystems update_
//! <table>
//!     <tr><td><b>Functionality</b></td><td><b>Done</b></td></tr>
//!     <tr><td>ElGamal over elliptic curves</td><td>x</td></tr>
//!     <tr><td>ElGamal over the integers</td><td>x</td></tr>
//!     <tr><td>Paillier</td><td>x</td></tr>
//!     <tr><td>RSA</td><td>x</td></tr>
//! </table>

#![warn(missing_docs, unused_imports)]

/// Functions for generating random prime numbers.
pub mod number_theory;

/// Random number generation that is consistent with the dependencies' requirements.
pub mod randomness;

/// Partially homomorphic cryptosystems with one key.
pub mod cryptosystems;

/// Partially homomorphic threshold cryptosystems that require multiple parties to decrypt.
mod threshold_cryptosystems;

use crate::randomness::SecureRng;

/// An asymmetric cryptosystem is a system of methods to encrypt plaintexts into ciphertexts, and
/// decrypt those ciphertexts back into plaintexts. Anyone who has access to the public key can
/// perform encryptions, but only those with the secret key can decrypt.
///
/// The struct that implements an `AsymmetricCryptosystem` will hold the general parameters of that
/// cryptosystem. Depending on the cryptosystem, those parameters could play an important role in
/// deciding the level of security. As such, each cryptosystem should clearly indicate these.
pub trait AsymmetricCryptosystem {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext;

    /// The type of the encryption key.
    type PublicKey;
    /// The type of the decryption key.
    type SecretKey;

    /// Generate a public and private key pair using a cryptographic RNG.
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext;

    /// Decrypt the ciphertext using the secret key and its related public key.
    fn decrypt(
        &self,
        rich_ciphertext: &RichCiphertext<Self::Ciphertext, Self::PublicKey>,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext;
}

/// Some cryptosystems do not require the public key to decrypt, as all the necessary information
/// is stored within the ciphertext and the secret key. For example, ElGamal when its group is
/// hard-coded.
pub trait DecryptDirectly {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext;

    /// The type of the decryption key.
    type SecretKey;

    /// Decrypt a ciphertext using the secret key directly, without requiring a rich ciphertext.
    fn decrypt_direct(
        &self,
        ciphertext: &Self::Ciphertext,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext;
}

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
pub struct DecryptionError;

/// An asymmetric threshold cryptosystem is a system of methods to encrypt plaintexts into
/// ciphertexts, but instead of having a single secret key to decrypt them back into plaintexts, we
/// require a given number of parties to decrypt with their own partial key. If enough parties
/// partially decrypt, the resulting shares can be combined into the original plaintext. Still,
/// anyone who has access to the public key can perform encryptions.
///
/// We denote a threshold cryptosystem using a tuple like (t, n). This means that t parties can
/// collectively decrypt, and that there are in total n partial keys.
///
/// The struct that implements an `AsymmetricThresholdCryptosystem` will hold the general parameters
/// of that cryptosystem. Depending on the cryptosystem, those parameters could play an important
/// role in deciding the level of security. As such, each cryptosystem should clearly indicate
/// these.
pub trait AsymmetricThresholdCryptosystem {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext;

    /// The type of the encryption key.
    type PublicKey;
    /// The type of the partial key.
    type PartialKey;

    /// The type of a decryption share, which can be combined with $t - 1$ other shares to finish
    /// decryption.
    type DecryptionShare;

    /// Generate a public and private key pair using a cryptographic RNG.
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext;

    /// Partially decrypt the ciphertext using a partial key and its related public key.
    fn partially_decrypt(
        &self,
        rich_ciphertext: &RichCiphertext<Self::Ciphertext, Self::PublicKey>,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare;

    /// Combine t decryption shares belonging to distinct partial keys to finish decryption.
    fn combine(
        &self,
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError>;
}
