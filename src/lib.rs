#![doc = include_str!("../README.md")]
#![warn(missing_docs, unused_imports)]

/// Functions for generating random prime numbers.
pub mod number_theory;

/// Random number generation that is consistent with the dependencies' requirements.
pub mod randomness;

/// Partially homomorphic cryptosystems with one key.
pub mod cryptosystems;

/// Partially homomorphic threshold cryptosystems that require multiple parties to decrypt.
pub mod threshold_cryptosystems;

/// Rich representation of a ciphertext that associates it with the corresponding public key.
/// This allows for performing homomorphic operations using operator overloading, among others.
pub struct RichCiphertext<'pk, C, PK> {
    ciphertext: C,
    public_key: &'pk PK,
}

/// Functionality to easily turn a ciphertext into a rich ciphertext
pub trait Enrichable<PK> {
    /// Enriches a ciphertext by associating it with a corresponding public key.
    fn enrich(self, public_key: &PK) -> RichCiphertext<Self, PK>
    where
        Self: Sized,
    {
        RichCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

/// General error that arises when decryption fails, for example because there were not enough
/// distinct decryption shares to decrypt a threshold ciphertext.
#[derive(Debug)]
pub struct DecryptionError;

/// The number of bits of security as compared to the AES cryptosystem. Check
/// https://www.keylength.com/en/4/ for recommendations.
pub enum BitsOfSecurity {
    /// Security that is equivalent to the security of the 2TDEA cryptosystem. This choice of
    /// parameters is not secure and is only used for legacy.
    AES80,
    /// This level of security is expected to be safe until 2030.
    AES112,
    /// Security that is equivalent to that of 128 bits in the AES cryptosystem. This level of
    /// security is expected to be safe until 2030 & beyond.
    AES128,
    /// Security that is equivalent to that of 192 bits in the AES cryptosystem. This level of
    /// security is expected to be safe until 2030 & beyond.
    AES192,
    /// Security that is equivalent to that of 256 bits in the AES cryptosystem. This level of
    /// security is expected to be safe until 2030 & beyond.
    AES256,
    /// Security that is equivalent to a number of bits `pk_bits` in accordance to the size of a
    /// public key modulus. Note that any number lower than 1024 is considered extremely insecure.
    Other {
        /// The number of bits in a public key (factoring) modulus.
        pk_bits: u32,
    },
}

impl BitsOfSecurity {
    fn to_public_key_bit_length(&self) -> u32 {
        match self {
            Self::AES80 => 1024,
            Self::AES112 => 2048,
            Self::AES128 => 3072,
            Self::AES192 => 7680,
            Self::AES256 => 15360,
            Self::Other { pk_bits } => *pk_bits,
        }
    }
}

impl Default for BitsOfSecurity {
    fn default() -> Self {
        Self::AES128
    }
}
