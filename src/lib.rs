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
//! ## Version 0.1.0
//! _Homomorphic cryptosystems update_
//! <table>
//!     <tr><td><b>Functionality</b></td><td><b>Done</b></td></tr>
//!     <tr><td>ElGamal over elliptic curves</td><td>x</td></tr>
//!     <tr><td>ElGamal over the integers</td><td> </td></tr>
//!     <tr><td>Paillier</td><td></td> </tr>
//!     <tr><td>RSA</td><td></td> </tr>
//! </table>

/// Functions for generating random prime numbers.
pub mod number_theory;

/// Random number generation that is consistent with the dependencies' requirements.
pub mod randomness;

/// Instances of the ElGamal cryptosystem.
pub mod el_gamal;
/// Implementation of the Paillier cryptosystem.
pub mod paillier;
/// Implementation of the RSA cryptosystem.
pub mod rsa;

use crate::randomness::SecureRng;

/// An asymmetric cryptosystem is a system of methods to encrypt plaintexts into ciphertexts, and
/// decrypt those ciphertexts back into plaintexts. Anyone who has access to the public key can
/// perform encryptions, but only those with the secret key can decrypt.
///
/// The struct that implements an AsymmetricCryptosystem will hold the general parameters of that
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

    /// Decrypt the ciphertext and its related public key using the secret key.
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

pub struct RichCiphertext<'pk, C, PK> {
    ciphertext: C,
    public_key: &'pk PK,
}

pub trait Enrichable<PK> {
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
