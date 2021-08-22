use crate::randomness::SecureRng;
use crate::{BitsOfSecurity, RichCiphertext};

/// Implementation of the ElGamal cryptosystem over an elliptic curve.
pub mod curve_el_gamal;
/// Implementation of the ElGamal cryptosystem over a safe prime group.
pub mod integer_el_gamal;
/// Implementation of the Paillier cryptosystem.
pub mod paillier;
/// Implementation of the RSA cryptosystem.
pub mod rsa;

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

    /// Generate a public and private key pair using a cryptographic RNG. The level of security is
    /// determined by the computational `security_param`.
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext;

    /// Decrypt the ciphertext using the secret key and its related public key.
    fn decrypt(
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
        ciphertext: &Self::Ciphertext,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext;
}
