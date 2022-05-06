use crate::cryptosystems::{DecryptionKey, EncryptionKey, AssociatedCiphertext};
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
/// The struct that implements an `NOfNCryptosystem` will hold the general parameters
/// of that cryptosystem. Depending on the cryptosystem, those parameters could play an important
/// role in deciding the level of security. As such, each cryptosystem should clearly indicate
/// these.
pub trait NOfNCryptosystem {
    type PublicKey: EncryptionKey;
    type SecretKey: PartialDecryptionKey<Self::PublicKey>;

    /// Sets up an instance of this cryptosystem with parameters satisfying the security parameter.
    fn setup(security_parameter: &BitsOfSecurity) -> Self;

    /// Generate a public key, and $n$ secret keys using a cryptographic RNG.
    fn generate_keys<R: SecureRng>(
        &self,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Vec<Self::SecretKey>);
}

pub trait PartialDecryptionKey<PK: EncryptionKey> {
    type DecryptionShare: DecryptionShare<PK>;

    fn partial_decrypt<'pk>(&self, ciphertext: &AssociatedCiphertext<'pk, PK::Ciphertext, PK>) -> Self::DecryptionShare {
        self.partial_decrypt_raw(ciphertext.public_key, &ciphertext.ciphertext)
    }
    fn partial_decrypt_raw(&self, public_key: &PK, ciphertext: &PK::Ciphertext) -> Self::DecryptionShare;
}

/// A `DecryptionShare` is the result of decrypting with a partial key. When enough of these shares
/// are combined, they reveal the actual decryption.
pub trait DecryptionShare<PK: EncryptionKey>: Sized {
    /// Combine $t$ decryption shares belonging to distinct partial keys to finish decryption. It is
    /// the responsibility of the programmer to supply the right number of decryption shares to
    /// this function.
    fn combine(
        decryption_shares: &[Self],
        public_key: &PK,
    ) -> Result<PK::Plaintext, DecryptionError>;
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
/// The struct that implements an `TOfNCryptosystem` will hold the general parameters
/// of that cryptosystem. Depending on the cryptosystem, those parameters could play an important
/// role in deciding the level of security. As such, each cryptosystem should clearly indicate
/// these.
pub trait TOfNCryptosystem {
    type PublicKey: EncryptionKey;
    type SecretKey: PartialDecryptionKey<Self::PublicKey>;

    /// Sets up an instance of this cryptosystem with parameters satisfying the security parameter.
    fn setup(security_parameter: &BitsOfSecurity) -> Self;

    /// Generate a public and private key pair using a cryptographic RNG.
    fn generate_keys<R: SecureRng>(
        &self,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Vec<Self::SecretKey>);
}
