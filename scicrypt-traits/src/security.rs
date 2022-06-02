/// The number of bits of security as compared to the AES cryptosystem. Check
/// <https://www.keylength.com/en/4/> for recommendations.
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
        pk_bits: u64,
    },
}

impl BitsOfSecurity {
    /// Returns the required modulus size for a given symmetric security level in the asymmetric
    /// setting.
    pub fn to_public_key_bit_length(&self) -> u64 {
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
