/// Implementation of the ElGamal cryptosystem over an elliptic curve.
pub mod curve_el_gamal;
/// Implementation of the ElGamal cryptosystem over a safe prime group.
pub mod integer_el_gamal;
/// Implementation of the Paillier cryptosystem.
pub mod paillier;
/// Implementation of the RSA cryptosystem.
pub mod rsa;

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
