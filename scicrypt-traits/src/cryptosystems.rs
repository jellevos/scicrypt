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
pub trait AsymmetricCryptosystem<'pk, PK: 'pk + EncryptionKey<Plaintext = SK::Plaintext, Ciphertext<'pk> = SK::Ciphertext<'pk>>, SK: DecryptionKey<'pk, PK>>: Clone {
    /// Sets up an instance of this cryptosystem with parameters satisfying the security parameter.
    fn setup(security_parameter: &BitsOfSecurity) -> Self;

    /// Generate a public and private key pair using a cryptographic RNG. The level of security is
    /// determined by the computational `security_parameter`.
    fn generate_keys<R: SecureRng>(
        &self,
        rng: &mut GeneralRng<R>,
    ) -> (PK, SK);
}

/// The encryption key.
pub trait EncryptionKey: Sized {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext<'pk> where Self: 'pk;

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<IntoP: Into<Self::Plaintext>, R: SecureRng>(&self, plaintext: IntoP, rng: &mut GeneralRng<R>) -> Self::Ciphertext<'_>;
}

/// The decryption key.
pub trait DecryptionKey<'pk, PK: 'pk + EncryptionKey<Ciphertext<'pk> = Self::Ciphertext<'pk>>> {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext<'p>;

    /// Decrypt the ciphertext using the secret key and its related public key.
    fn decrypt(&self, associated_ciphertext: &Self::Ciphertext<'pk>) -> Self::Plaintext;
}

// pub trait AssociatedCiphertext<PK: PublicKey<Ciphertext = Self::Ciphertext>>: Sized {
//     type Ciphertext: Associable<PK, Self>;
//
//     fn extract_ciphertext(self) -> Self::Ciphertext;
// }
//
// /// Functionality to easily turn a ciphertext into an associated ciphertext
// pub trait Associable<PK: PublicKey<Ciphertext = Self>, AC: AssociatedCiphertext<PK, Ciphertext = Self>> {
//     /// Enriches a ciphertext by associating it with a corresponding public key.
//     fn associate(self, public_key: &PK) -> AC;
// }
