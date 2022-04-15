use crate::randomness::GeneralRng;
use crate::randomness::SecureRng;
use crate::security::BitsOfSecurity;

/// An asymmetric cryptosystem is a system of methods to encrypt plaintexts into ciphertexts, and
/// decrypt those ciphertexts back into plaintexts. Anyone who has access to the public key can
/// perform encryptions, but only those with the secret key can decrypt.
///
/// The struct that implements an `AsymmetricCryptosystem` will hold the general parameters of that
/// cryptosystem. Depending on the cryptosystem, those parameters could play an important role in
/// deciding the level of security. As such, each cryptosystem should clearly indicate these.
pub trait AsymmetricCryptosystem<PK: PublicKey<Plaintext = SK::Plaintext, Ciphertext = SK::Ciphertext>, SK: SecretKey<PK>>: Copy {
    /// Generate a public and private key pair using a cryptographic RNG. The level of security is
    /// determined by the computational `security_parameter`.
    fn generate_keys<R: SecureRng>(
        security_parameter: &BitsOfSecurity,
        rng: &mut GeneralRng<R>,
    ) -> (PK, SK);
}

/// The encryption key.
pub trait PublicKey {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext;

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<IntoP: Into<Self::Plaintext>, R: SecureRng>(&self, plaintext: IntoP, rng: &mut GeneralRng<R>) -> AssociatedCiphertext<Self, Self::Ciphertext> where Self: Sized;
}

/// The decryption key.
pub trait SecretKey<PK: PublicKey<Ciphertext = Self::Ciphertext>> {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext;

    /// Decrypt the ciphertext using the secret key and its related public key.
    fn decrypt(&self, associated_ciphertext: &AssociatedCiphertext<PK, Self::Ciphertext>) -> Self::Plaintext;
}

/// Rich representation of a ciphertext that associates it with the corresponding public key.
/// This allows for performing homomorphic operations using operator overloading, among others.
pub struct AssociatedCiphertext<'pk, PK: PublicKey<Ciphertext = C>, C> {
    pub ciphertext: C,
    pub public_key: &'pk PK,
}

/// Functionality to easily turn a ciphertext into an associated ciphertext
pub trait Associable<PK: PublicKey<Ciphertext = Self>> {
    /// Enriches a ciphertext by associating it with a corresponding public key.
    fn associate(self, public_key: &PK) -> AssociatedCiphertext<PK, Self> where Self: Sized {
        AssociatedCiphertext {
            ciphertext: self,
            public_key
        }
    }
}
