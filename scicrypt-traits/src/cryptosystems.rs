use crate::randomness::SecureRng;
use crate::security::BitsOfSecurity;
use crate::Enrichable;

/// An asymmetric cryptosystem is a system of methods to encrypt plaintexts into ciphertexts, and
/// decrypt those ciphertexts back into plaintexts. Anyone who has access to the public key can
/// perform encryptions, but only those with the secret key can decrypt.
///
/// The struct that implements an `AsymmetricCryptosystem` will hold the general parameters of that
/// cryptosystem. Depending on the cryptosystem, those parameters could play an important role in
/// deciding the level of security. As such, each cryptosystem should clearly indicate these.
pub trait AsymmetricCryptosystem<'pk> {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext: Enrichable<'pk, Self::PublicKey, Self::RichCiphertext<'pk>>;
    /// Rich representation of a ciphertext that associates it with the corresponding public key.
    /// This allows for performing homomorphic operations using operator overloading, among others.
    type RichCiphertext<'p>;

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
    fn decrypt<'p>(
        rich_ciphertext: &Self::RichCiphertext<'p>,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext;
}
