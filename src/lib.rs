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

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use std::ops::{Add, Mul};
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
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>
    (&self, rng: &mut SecureRng<R>) -> (Self::PublicKey, Self::SecretKey);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>
    (&self, plaintext: &Self::Plaintext, public_key: &Self::PublicKey, rng: &mut SecureRng<R>)
        -> Self::Ciphertext;

    /// Decrypt the ciphertext using the secret key.
    fn decrypt(&self, ciphertext: &Self::Ciphertext, secret_key: &Self::SecretKey)
        -> Self::Plaintext;
}

/// ElGamal over the Ristretto-encoded Curve25519 elliptic curve. The curve is provided by the
/// `curve25519-dalek` crate. ElGamal is a partially homomorphic cryptosystem.
pub struct CurveElGamal;

/// ElGamal ciphertext containing curve points. The addition operator on the ciphertext is
/// reflected as the curve operation on the associated plaintext.
#[derive(Debug, PartialEq)]
pub struct CurveElGamalCiphertext {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

impl AsymmetricCryptosystem for CurveElGamal {
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;

    type PublicKey = RistrettoPoint;
    type SecretKey = Scalar;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut SecureRng<R>) -> (Self::PublicKey, Self::SecretKey) {
        let secret_key = Scalar::random(rng.rng());
        let public_key = &secret_key * &RISTRETTO_BASEPOINT_TABLE;

        (public_key, secret_key)
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(&self, plaintext: &Self::Plaintext, public_key: &Self::PublicKey, rng: &mut SecureRng<R>) -> Self::Ciphertext {
        let y = Scalar::random(rng.rng());

        CurveElGamalCiphertext {
            c1: &y * &RISTRETTO_BASEPOINT_TABLE,
            c2: plaintext + &y * public_key,
        }
    }

    fn decrypt(&self, ciphertext: &Self::Ciphertext, secret_key: &Self::SecretKey) -> Self::Plaintext {
        ciphertext.c2 - secret_key * &ciphertext.c1
    }
}

impl Add for &CurveElGamalCiphertext {
    type Output = CurveElGamalCiphertext;

    /// Homomorphic operation between two ElGamal ciphertexts.
    fn add(self, rhs: Self) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl Mul<&Scalar> for &CurveElGamalCiphertext {
    type Output = CurveElGamalCiphertext;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.c1 * rhs,
            c2: self.c2 * rhs,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{CurveElGamal, AsymmetricCryptosystem};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use crate::randomness::SecureRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = SecureRng::new(OsRng);

        let curve_elgamal = CurveElGamal;
        let (pk, sk) = curve_elgamal.generate_keys(&mut rng);

        let ciphertext = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                               &mut rng);

        assert_eq!(RISTRETTO_BASEPOINT_POINT, curve_elgamal.decrypt(&ciphertext, &sk));
    }

    #[test]
    fn test_probabilistic_encryption() {
        let mut rng = SecureRng::new(OsRng);

        let curve_elgamal = CurveElGamal;
        let (pk, _) = curve_elgamal.generate_keys(&mut rng);

        let ciphertext1 = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                                &mut rng);
        let ciphertext2 = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                                &mut rng);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = SecureRng::new(OsRng);

        let curve_elgamal = CurveElGamal;
        let (pk, sk) = curve_elgamal.generate_keys(&mut rng);

        let ciphertext = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                               &mut rng);
        let ciphertext_twice = &ciphertext + &ciphertext;

        assert_eq!(&Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
                   curve_elgamal.decrypt(&ciphertext_twice, &sk));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = SecureRng::new(OsRng);

        let curve_elgamal = CurveElGamal;
        let (pk, sk) = curve_elgamal.generate_keys(&mut rng);

        let ciphertext = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                               &mut rng);
        let ciphertext_thrice = &ciphertext * &Scalar::from(3u64);

        assert_eq!(&Scalar::from(3u64) * &RISTRETTO_BASEPOINT_POINT,
                   curve_elgamal.decrypt(&ciphertext_thrice, &sk));
    }

}
