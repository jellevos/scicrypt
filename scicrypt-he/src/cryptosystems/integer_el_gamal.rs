//! Here is an example of how to generates a key pair and encrypt a plaintext integer using the ElGamal public key.
//! ```
//! use scicrypt_traits::randomness::GeneralRng;
//! use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
//! use scicrypt_traits::security::BitsOfSecurity;
//! use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey};
//! use rand_core::OsRng;
//! use scicrypt_bigint::UnsignedInteger;
//!
//! let mut rng = GeneralRng::new(OsRng);
//! let el_gamal = IntegerElGamal::setup(&Default::default());
//! let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
//! let ciphertext = public_key.encrypt(&UnsignedInteger::from(5), &mut rng);
//! ```

use crate::constants::{SAFE_PRIME_1024, SAFE_PRIME_2048, SAFE_PRIME_3072};
use scicrypt_bigint::UnsignedInteger;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicMultiplication;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use serde::{Deserialize, Serialize};

/// Multiplicatively homomorphic ElGamal over a safe prime group where the generator is 4.
///
/// As an example we compute the product between 4 and 6 using ElGamal's homomorphic property.
/// ```
/// # use scicrypt_traits::randomness::GeneralRng;
/// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
/// # use scicrypt_traits::security::BitsOfSecurity;
/// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
/// # use scicrypt_bigint::UnsignedInteger;
/// # use rand_core::OsRng;
/// let mut rng = GeneralRng::new(OsRng);
/// let el_gamal = IntegerElGamal::setup(&Default::default());
/// let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
///
/// let ciphertext_1 = public_key.encrypt(&UnsignedInteger::from(4), &mut rng);
/// let ciphertext_2 = public_key.encrypt(&UnsignedInteger::from(6), &mut rng);
///
/// println!("[4] * [6] = [{}]", secret_key.decrypt(&(&ciphertext_1 * &ciphertext_2)));
/// // Prints: "[4] * [6] = [24]".
/// ```
#[derive(Clone)]
pub struct IntegerElGamal {
    modulus: UnsignedInteger,
}

/// Public key containing the ElGamal encryption key and the modulus of the group.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct IntegerElGamalPK {
    /// Generator for encrypting
    pub h: UnsignedInteger,
    /// Modulus of public key
    pub modulus: UnsignedInteger,
}

/// ElGamal ciphertext of integers.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct IntegerElGamalCiphertext {
    /// First part of ciphertext
    pub c1: UnsignedInteger,
    /// Second part of ciphertext
    pub c2: UnsignedInteger,
}

impl Associable<IntegerElGamalPK> for IntegerElGamalCiphertext {}

/// Decryption key for Integer-based ElGamal
pub struct IntegerElGamalSK {
    pub(crate) key: UnsignedInteger,
}

impl AsymmetricCryptosystem for IntegerElGamal {
    type PublicKey = IntegerElGamalPK;
    type SecretKey = IntegerElGamalSK;

    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        let public_key_len = security_param.to_public_key_bit_length();
        IntegerElGamal {
            modulus: UnsignedInteger::from_string(
                match public_key_len {
                    1024 => SAFE_PRIME_1024.to_string(),
                    2048 => SAFE_PRIME_2048.to_string(),
                    3072 => SAFE_PRIME_3072.to_string(),
                    _ => panic!("No parameters available for this security parameter"),
                },
                16,
                public_key_len,
            ),
        }
    }

    /// Generates a fresh ElGamal keypair.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// let el_gamal = IntegerElGamal::setup(&Default::default());
    /// let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
    /// ```
    fn generate_keys<R: SecureRng>(
        &self,
        rng: &mut GeneralRng<R>,
    ) -> (IntegerElGamalPK, IntegerElGamalSK) {
        let q = &self.modulus >> 1;
        let secret_key = UnsignedInteger::random_below(&q, rng);
        let public_key = UnsignedInteger::from(4u64).pow_mod(&secret_key, &self.modulus);

        (
            IntegerElGamalPK {
                h: public_key,
                modulus: self.modulus.clone(),
            },
            IntegerElGamalSK { key: secret_key },
        )
    }
}

impl EncryptionKey for IntegerElGamalPK {
    type Input = UnsignedInteger;
    type Plaintext = UnsignedInteger;
    type Ciphertext = IntegerElGamalCiphertext;
    type Randomness = UnsignedInteger;

    fn encrypt_without_randomness(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: UnsignedInteger::new(1, 1),
            c2: plaintext.clone() % &self.modulus,
        }
    }

    fn randomize<R: SecureRng>(
        &self,
        ciphertext: Self::Ciphertext,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        let q = &self.modulus >> 1;
        let y = UnsignedInteger::random_below(&q, rng);

        self.randomize_with(ciphertext, &y)
    }

    fn randomize_with(
        &self,
        ciphertext: Self::Ciphertext,
        randomness: &Self::Randomness,
    ) -> Self::Ciphertext {
        // FIXME: C1 should also be multiplied, otherwise this is only a valid randomization when c1 = 1.
        IntegerElGamalCiphertext {
            c1: UnsignedInteger::from(4u64).pow_mod(randomness, &self.modulus),
            c2: (&ciphertext.c2 * &self.h.pow_mod(randomness, &self.modulus)) % &self.modulus,
        }
    }
}

impl DecryptionKey<IntegerElGamalPK> for IntegerElGamalSK {
    /// Decrypts an ElGamal ciphertext using the secret key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
    /// # use scicrypt_bigint::UnsignedInteger;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let el_gamal = IntegerElGamal::setup(&Default::default());
    /// # let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
    /// # let ciphertext = public_key.encrypt(&UnsignedInteger::from(5), &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt_raw(
        &self,
        public_key: &IntegerElGamalPK,
        ciphertext: &IntegerElGamalCiphertext,
    ) -> UnsignedInteger {
        (&ciphertext.c2
            * &ciphertext
                .c1
                .pow_mod(&self.key, &public_key.modulus)
                .invert(&public_key.modulus)
                .unwrap())
            % &public_key.modulus
    }

    fn decrypt_identity_raw(
        &self,
        public_key: &IntegerElGamalPK,
        ciphertext: &<IntegerElGamalPK as EncryptionKey>::Ciphertext,
    ) -> bool {
        ciphertext.c2 == ciphertext.c1.pow_mod(&self.key, &public_key.modulus)
    }
}

impl HomomorphicMultiplication for IntegerElGamalPK {
    fn mul(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: (&ciphertext_a.c1 * &ciphertext_b.c1) % &self.modulus,
            c2: (&ciphertext_a.c2 * &ciphertext_b.c2) % &self.modulus,
        }
    }

    fn pow(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: ciphertext.c1.pow_mod(input, &self.modulus),
            c2: ciphertext.c2.pow_mod(input, &self.modulus),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::integer_el_gamal::IntegerElGamal;
    use rand_core::OsRng;
    use scicrypt_bigint::UnsignedInteger;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(19u64), &mut rng);

        assert_eq!(UnsignedInteger::from(19u64), sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_encrypt_decrypt_identity() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(1), &mut rng);

        assert!(sk.decrypt_identity(&ciphertext));
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_b = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_twice = &ciphertext_a * &ciphertext_b;

        assert_eq!(UnsignedInteger::from(49u64), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(9u64), &mut rng);
        let ciphertext_twice = ciphertext.pow(&UnsignedInteger::from(4u64));

        assert_eq!(
            UnsignedInteger::from(6561u64),
            sk.decrypt(&ciphertext_twice)
        );
    }
}
