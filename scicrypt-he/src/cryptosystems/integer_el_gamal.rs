use crate::constants::{SAFE_PRIME_1024, SAFE_PRIME_2048, SAFE_PRIME_3072};
use scicrypt_bigint::BigInteger;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicMultiplication;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;

/// Multiplicatively homomorphic ElGamal over a safe prime group where the generator is 4.
///
/// As an example we compute the product between 4 and 6 using ElGamal's homomorphic property.
/// ```
/// # use scicrypt_traits::randomness::GeneralRng;
/// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
/// # use scicrypt_traits::security::BitsOfSecurity;
/// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
/// # use rand_core::OsRng;
/// let mut rng = GeneralRng::new(OsRng);
/// let el_gamal = IntegerElGamal::setup(&Default::default());
/// let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
///
/// let ciphertext_1 = public_key.encrypt(&Integer::from(4), &mut rng);
/// let ciphertext_2 = public_key.encrypt(&Integer::from(6), &mut rng);
///
/// println!("[4] * [6] = [{}]", secret_key.decrypt(&(ciphertext_1 * ciphertext_2)));
/// // Prints: "[4] * [6] = [24]".
/// ```
#[derive(Clone)]
pub struct IntegerElGamal {
    modulus: BigInteger,
}

/// Public key containing the ElGamal encryption key and the modulus of the group.
#[derive(PartialEq, Eq, Debug)]
pub struct IntegerElGamalPK {
    pub(crate) h: BigInteger,
    pub(crate) modulus: BigInteger,
}

/// ElGamal ciphertext of integers.
pub struct IntegerElGamalCiphertext {
    pub(crate) c1: BigInteger,
    pub(crate) c2: BigInteger,
}

impl Associable<IntegerElGamalPK> for IntegerElGamalCiphertext {}

/// Decryption key for Integer-based ElGamal
pub struct IntegerElGamalSK {
    pub(crate) key: BigInteger,
}

impl AsymmetricCryptosystem for IntegerElGamal {
    type PublicKey = IntegerElGamalPK;
    type SecretKey = IntegerElGamalSK;

    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        let public_key_len = security_param.to_public_key_bit_length();
        IntegerElGamal {
            modulus: BigInteger::from_string(
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
        let secret_key = BigInteger::random_below(&q, rng);
        let public_key = BigInteger::from(4u64).pow_mod(&secret_key, &self.modulus);

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
    type Input = BigInteger;
    type Plaintext = BigInteger;
    type Ciphertext = IntegerElGamalCiphertext;

    /// Encrypts an integer using the public key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey};
    /// # use rand_core::OsRng;
    /// # use rug::Integer;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let el_gamal = IntegerElGamal::setup(&Default::default());
    /// # let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
    /// let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
    /// ```
    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &BigInteger,
        rng: &mut GeneralRng<R>,
    ) -> IntegerElGamalCiphertext {
        let q = &self.modulus >> 1;
        let y = BigInteger::random_below(&q, rng);

        IntegerElGamalCiphertext {
            c1: BigInteger::from(4u64).pow_mod(&y, &self.modulus),
            c2: (plaintext * &self.h.pow_mod(&y, &self.modulus)) % &self.modulus,
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
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let el_gamal = IntegerElGamal::setup(&Default::default());
    /// # let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
    /// # let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt_raw(
        &self,
        public_key: &IntegerElGamalPK,
        ciphertext: &IntegerElGamalCiphertext,
    ) -> BigInteger {
        (&ciphertext.c2
            * &ciphertext
                .c1
                .pow_mod(&self.key, &public_key.modulus)
                .invert(&public_key.modulus)
                .unwrap())
            % &public_key.modulus
    }
}

impl HomomorphicMultiplication for IntegerElGamalPK {
    fn mul(
        &self,
        ciphertext_a: Self::Ciphertext,
        ciphertext_b: Self::Ciphertext,
    ) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: (&ciphertext_a.c1 * &ciphertext_b.c1) % &self.modulus,
            c2: (&ciphertext_a.c2 * &ciphertext_b.c2) % &self.modulus,
        }
    }

    fn pow(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: ciphertext.c1.pow_mod(&input, &self.modulus),
            c2: ciphertext.c2.pow_mod(&input, &self.modulus),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::integer_el_gamal::IntegerElGamal;
    use rand_core::OsRng;
    use scicrypt_bigint::BigInteger;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&BigInteger::from(19u64), &mut rng);

        assert_eq!(BigInteger::from(19u64), sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_homomorphic_mul() {
        // TODO: Sometimes fails
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&BigInteger::from(7u64), &mut rng);
        let ciphertext_b = pk.encrypt(&BigInteger::from(7u64), &mut rng);
        let ciphertext_twice = ciphertext_a * ciphertext_b;

        assert_eq!(BigInteger::from(49u64), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&BigInteger::from(9u64), &mut rng);
        let ciphertext_twice = ciphertext.pow(BigInteger::from(4u64));

        assert_eq!(BigInteger::from(6561u64), sk.decrypt(&ciphertext_twice));
    }
}
