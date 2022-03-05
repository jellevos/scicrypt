use crate::randomness::GeneralRng;
use crate::randomness::SecureRng;
use crate::security::BitsOfSecurity;
use crate::DecryptionError;

/// An asymmetric threshold cryptosystem is a system of methods to encrypt plaintexts into
/// ciphertexts, but instead of having a single secret key to decrypt them back into plaintexts, we
/// require a given number of parties to decrypt with their own partial key. If enough parties
/// partially decrypt, the resulting shares can be combined into the original plaintext. Still,
/// anyone who has access to the public key can perform encryptions.
///
/// We denote a threshold cryptosystem using a tuple like (t, n). This means that t parties can
/// collectively decrypt, and that there are in total n partial keys. In this special case, all n
/// keys must be used to decrypt.
///
/// The struct that implements an `AsymmetricNOfNCryptosystem` will hold the general parameters
/// of that cryptosystem. Depending on the cryptosystem, those parameters could play an important
/// role in deciding the level of security. As such, each cryptosystem should clearly indicate
/// these.
pub trait AsymmetricNOfNCryptosystem {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext;
    /// Rich representation of a ciphertext that associates it with the corresponding public key.
    /// This allows for performing homomorphic operations using operator overloading, among others.
    type RichCiphertext<'p>;

    /// The type of the encryption key.
    type PublicKey;
    /// The type of the partial key.
    type PartialKey;

    /// The type of a decryption share, which can be combined with $t - 1$ other shares to finish
    /// decryption.
    type DecryptionShare;

    /// Generate a public and private key pair using a cryptographic RNG.
    fn generate_keys<R: SecureRng>(
        security_param: &BitsOfSecurity,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: SecureRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext;

    /// Partially decrypt the ciphertext using a partial key and its related public key.
    fn partially_decrypt<'p>(
        rich_ciphertext: &Self::RichCiphertext<'p>,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare;

    /// Combine t decryption shares belonging to distinct partial keys to finish decryption.  It is
    /// the responsibility of the programmer to supply the right number of decryption shares to
    /// this function.
    fn combine(
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError>;
}

/// An asymmetric threshold cryptosystem is a system of methods to encrypt plaintexts into
/// ciphertexts, but instead of having a single secret key to decrypt them back into plaintexts, we
/// require a given number of parties to decrypt with their own partial key. If enough parties
/// partially decrypt, the resulting shares can be combined into the original plaintext. Still,
/// anyone who has access to the public key can perform encryptions.
///
/// We denote a threshold cryptosystem using a tuple like (t, n). This means that t parties can
/// collectively decrypt, and that there are in total n partial keys.
///
/// The struct that implements an `AsymmetricTOfNCryptosystem` will hold the general parameters
/// of that cryptosystem. Depending on the cryptosystem, those parameters could play an important
/// role in deciding the level of security. As such, each cryptosystem should clearly indicate
/// these.
pub trait AsymmetricTOfNCryptosystem {
    /// The type of the plaintexts to be encrypted.
    type Plaintext;
    /// The type of the encrypted plaintexts.
    type Ciphertext;
    /// Rich representation of a ciphertext that associates it with the corresponding public key.
    /// This allows for performing homomorphic operations using operator overloading, among others.
    type RichCiphertext<'p>;

    /// The type of the encryption key.
    type PublicKey;
    /// The type of the partial key.
    type PartialKey;

    /// The type of a decryption share, which can be combined with $t - 1$ other shares to finish
    /// decryption.
    type DecryptionShare;

    /// Generate a public and private key pair using a cryptographic RNG.
    fn generate_keys<R: SecureRng>(
        security_param: &BitsOfSecurity,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>);

    /// Encrypt the plaintext using the public key and a cryptographic RNG.
    fn encrypt<R: SecureRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext;

    /// Partially decrypt the ciphertext using a partial key and its related public key.
    fn partially_decrypt<'p>(
        rich_ciphertext: &Self::RichCiphertext<'p>,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare;

    /// Combine t decryption shares belonging to distinct partial keys to finish decryption. It is
    /// the responsibility of the programmer to supply the right number of decryption shares to
    /// this function.
    fn combine(
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError>;
}
