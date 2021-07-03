use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use std::ops::Add;

/// An asymmetric cryptosystem is a system of methods to encrypt plaintexts into ciphertexts, and
/// decrypt those ciphertexts back into plaintexts. Anyone who has access to the public key can
/// perform encryptions, but only those with the secret key can decrypt.
///
/// The struct that implements an AsymmetricCryptosystem will hold the general parameters of that
/// cryptosystem. Depending on the cryptosystem, those parameters could play an important role in
/// deciding the level of security. As such, each cryptosystem should clearly indicate these.
trait AsymmetricCryptosystem {
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
    (&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>
    (&self, plaintext: &Self::Plaintext, public_key: &Self::PublicKey, rng: &mut R) -> Self::Ciphertext;

    /// Decrypt the ciphertext using the secret key.
    fn decrypt(&self, ciphertext: &Self::Ciphertext, secret_key: &Self::SecretKey) -> Self::Plaintext;
}

/// ElGamal over the Ristretto-encoded Curve25519 elliptic curve. The curve is provided by the
/// `curve25519-dalek` crate. ElGamal is a partially homomorphic cryptosystem.
struct CurveElGamal;

/// ElGamal ciphertext containing curve points. The addition operator on the ciphertext is
/// reflected as the curve operation on the associated plaintext.
#[derive(Debug, PartialEq)]
struct CurveElGamalCiphertext {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

impl AsymmetricCryptosystem for CurveElGamal {
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;

    type PublicKey = RistrettoPoint;
    type SecretKey = Scalar;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let secret_key = Scalar::random(rng);
        let public_key = &secret_key * &RISTRETTO_BASEPOINT_TABLE;

        (public_key, secret_key)
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(&self, plaintext: &Self::Plaintext, public_key: &Self::PublicKey, rng: &mut R) -> Self::Ciphertext {
        let y = Scalar::random(rng);

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

#[cfg(test)]
mod tests {
    use crate::{CurveElGamal, AsymmetricCryptosystem};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let curve_elgamal = CurveElGamal{};
        let (pk, sk) = curve_elgamal.generate_keys(&mut OsRng);

        let ciphertext = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                               &mut OsRng);

        assert_eq!(RISTRETTO_BASEPOINT_POINT, curve_elgamal.decrypt(&ciphertext, &sk));
    }

    #[test]
    fn test_probabilistic_encryption() {
        let curve_elgamal = CurveElGamal{};
        let (pk, _) = curve_elgamal.generate_keys(&mut OsRng);

        let ciphertext1 = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                               &mut OsRng);
        let ciphertext2 = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                               &mut OsRng);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_homomorphism() {
        let curve_elgamal = CurveElGamal{};
        let (pk, sk) = curve_elgamal.generate_keys(&mut OsRng);

        let ciphertext = curve_elgamal.encrypt(&RISTRETTO_BASEPOINT_POINT,
                                               &pk,
                                               &mut OsRng);
        let ciphertext_twice = &ciphertext + &ciphertext;

        assert_eq!(&Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
                   curve_elgamal.decrypt(&ciphertext_twice, &sk));
    }

}
