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
pub trait AsymmetricCryptosystem<'pk, PK: EncryptionKey<'pk, P, C>, SK: DecryptionKey<P, C>, P, C>:
    Clone
{
    /// Sets up an instance of this cryptosystem with parameters satisfying the security parameter.
    fn setup(security_parameter: &BitsOfSecurity) -> Self;

    /// Generate a public and private key pair using a cryptographic RNG. The level of security is
    /// determined by the computational `security_parameter`.
    fn generate_keys<R: SecureRng>(&self, rng: &mut GeneralRng<R>) -> (PK, SK);
}

/// The encryption key.
pub trait EncryptionKey<'pk, P, C>: Sized {
    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<IntoP: Into<P>, R: SecureRng>(
        &'pk self,
        plaintext: IntoP,
        rng: &mut GeneralRng<R>,
    ) -> C
    where
        C: 'pk;
}

/// The decryption key.
pub trait DecryptionKey<P, C> {
    /// Decrypt the ciphertext using the secret key and its related public key.
    fn decrypt(&self, associated_ciphertext: &C) -> P;
}

/// Functionality to easily turn a ciphertext into an associated ciphertext
pub trait Associable<'pk, PK: EncryptionKey<'pk, P, AC>, AC: 'pk, P>: Sized {
    /// Enriches a ciphertext by associating it with a corresponding public key.
    fn associate(self, public_key: &'pk PK) -> AC;
}
