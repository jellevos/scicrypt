use crate::randomness::GeneralRng;
use crate::randomness::SecureRng;
use crate::security::BitsOfSecurity;
use std::fmt::Debug;

/// An asymmetric cryptosystem is a system of methods to encrypt plaintexts into ciphertexts, and
/// decrypt those ciphertexts back into plaintexts. Anyone who has access to the public key can
/// perform encryptions, but only those with the secret key can decrypt.
///
/// The struct that implements an `AsymmetricCryptosystem` will hold the general parameters of that
/// cryptosystem. Depending on the cryptosystem, those parameters could play an important role in
/// deciding the level of security. As such, each cryptosystem should clearly indicate these.
pub trait AsymmetricCryptosystem {
    /// The public key, used for encrypting plaintexts.
    type PublicKey;
    /// The secret key, used for decrypting ciphertexts.
    type SecretKey;

    /// Sets up an instance of this cryptosystem with parameters satisfying the security parameter.
    fn setup(security_parameter: &BitsOfSecurity) -> Self;

    /// Generate a public and private key pair using a cryptographic RNG. The level of security is
    /// determined by the computational `security_parameter`.
    fn generate_keys<R: SecureRng>(
        &self,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey);
}

/// The encryption key.
pub trait EncryptionKey: Sized + Debug + PartialEq {
    /// Input is the type used to multiply additive ciphertexts or exponentiate multiplicative ciphertexts.
    type Input;

    /// The type of the plaintext to be encrypted.
    type Plaintext;

    /// The type of an encrypted plaintext, i.e. a ciphertext.
    type Ciphertext: Associable<Self>;

    /// Encrypt the plaintext using the public key and a cryptographic RNG and immediately associate it with the public key.
    fn encrypt<'pk, R: SecureRng>(
        &'pk self,
        plaintext: &Self::Plaintext,
        rng: &mut GeneralRng<R>,
    ) -> AssociatedCiphertext<'pk, Self::Ciphertext, Self> {
        self.encrypt_raw(plaintext, rng).associate(self)
    }

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &Self::Plaintext,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext;
}

/// The decryption key.
pub trait DecryptionKey<PK: EncryptionKey> {
    /// Decrypt the associated ciphertext using the secret key.
    fn decrypt<'pk>(
        &self,
        ciphertext: &AssociatedCiphertext<'pk, PK::Ciphertext, PK>,
    ) -> PK::Plaintext {
        self.decrypt_raw(ciphertext.public_key, &ciphertext.ciphertext)
    }

    /// Decrypt the ciphertext using the secret key and its related public key.
    fn decrypt_raw(&self, public_key: &PK, ciphertext: &PK::Ciphertext) -> PK::Plaintext;

    /// Uses both the secret material from the decryption key and the encryption key to encrypt faster than with only the encryption key.
    /// This method is always implemented, but it defaults to simply encrypting without the secret key.
    fn encrypt_fast<'pk, R: SecureRng>(
        &'pk self,
        public_key: &'pk PK,
        plaintext: &PK::Plaintext,
        rng: &mut GeneralRng<R>,
    ) -> AssociatedCiphertext<'pk, PK::Ciphertext, PK> {
        self.encrypt_fast_raw(public_key, plaintext, rng)
            .associate(public_key)
    }

    /// Uses both the secret material from the decryption key and the encryption key to encrypt faster than with only the encryption key.
    /// This method is always implemented, but it defaults to simply encrypting without the secret key.
    fn encrypt_fast_raw<R: SecureRng>(
        &self,
        public_key: &PK,
        plaintext: &PK::Plaintext,
        rng: &mut GeneralRng<R>,
    ) -> PK::Ciphertext {
        public_key.encrypt_raw(plaintext, rng)
    }
}

#[derive(PartialEq, Eq, Debug)]
/// An AssociatedCiphertext associates a ciphertext with a reference to the corresponding public key to make homomorphic operations and decrypting more ergonomic.
pub struct AssociatedCiphertext<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C>> {
    /// A potentially homomorphic ciphertext
    pub ciphertext: C,
    /// The related public key
    pub public_key: &'pk PK,
}

/// Functionality to easily turn a ciphertext into an associated ciphertext
pub trait Associable<PK: EncryptionKey<Ciphertext = Self>>: Sized {
    /// 'Enriches' a ciphertext by associating it with a corresponding public key. This allows to overlead operators for homomorphic operations.
    fn associate(self, public_key: &PK) -> AssociatedCiphertext<'_, Self, PK> {
        AssociatedCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

/// The Verification key.
pub trait VerificationKey {
    /// The type of the plaintext to be signed.
    type Plaintext;

    /// The type of a signature.
    type Signature;

    /// Verify the Signature on the plaintext message using the (public) Verification key.
    fn verify(&self, signature: &Self::Signature, plaintext: &Self::Plaintext) -> bool;
}

/// The Signing key.
pub trait SigningKey<VK: VerificationKey> {
    /// Sign the plaintext message using the (secret) Signing key.
    fn sign<R: SecureRng>(
        &self,
        plaintext: &VK::Plaintext,
        public_key: &VK,
        rng: &mut GeneralRng<R>,
    ) -> VK::Signature;
}
