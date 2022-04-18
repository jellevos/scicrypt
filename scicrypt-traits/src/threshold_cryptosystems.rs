use crate::cryptosystems::{EncryptionKey, DecryptionKey};
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
pub trait NOfNCryptosystem<'pk, PK: 'pk + EncryptionKey<Plaintext = DS::Plaintext, Ciphertext<'pk> = SK::Ciphertext<'pk>>, SK: DecryptionKey<'pk, PK>, DS: DecryptionShare>: Clone {
    /// Sets up an instance of this cryptosystem with parameters satisfying the security parameter.
    fn setup(security_parameter: &BitsOfSecurity) -> Self;

    /// Generate a public key, and $n$ secret keys using a cryptographic RNG.
    fn generate_keys<R: SecureRng>(
        &self,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (PK, Vec<SK>);
}

/// A `DecryptionShare` is the result of decrypting with a partial key. When enough of these shares
/// are combined, they reveal the actual decryption.
pub trait DecryptionShare: Sized {
    /// The type of the plaintext retrieved when decryption shares are combined.
    type Plaintext;
    /// The public key that created the original ciphertexts.
    type PublicKey;

    /// Combine $t$ decryption shares belonging to distinct partial keys to finish decryption. It is
    /// the responsibility of the programmer to supply the right number of decryption shares to
    /// this function.
    fn combine(
        decryption_shares: &[Self],
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
/// The struct that implements an `TOfNCryptosystem` will hold the general parameters
/// of that cryptosystem. Depending on the cryptosystem, those parameters could play an important
/// role in deciding the level of security. As such, each cryptosystem should clearly indicate
/// these.
pub trait TOfNCryptosystem<'pk, PK: 'pk + EncryptionKey<Plaintext = DS::Plaintext, Ciphertext<'pk> = SK::Ciphertext<'pk>>, SK: DecryptionKey<'pk, PK>, DS: DecryptionShare>: Clone {
    /// Sets up an instance of this cryptosystem with parameters satisfying the security parameter.
    fn setup(security_parameter: &BitsOfSecurity) -> Self;

    /// Generate a public and private key pair using a cryptographic RNG.
    fn generate_keys<R: SecureRng>(
        &self,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (PK, Vec<SK>);
}
