use rug::Integer;
use scicrypt_numbertheory::gen_safe_prime;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::Enrichable;
use std::ops::{Mul, Rem};

/// Multiplicatively homomorphic ElGamal over a safe prime group where the generator is 4.
///
/// As an example we compute the product between 4 and 6 using ElGamal's homomorphic property.
/// ```
/// # use scicrypt_traits::randomness::SecureRng;
/// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
/// # use scicrypt_traits::security::BitsOfSecurity;
/// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
/// # use scicrypt_traits::Enrichable;
/// # use rand_core::OsRng;
/// # use rug::Integer;
/// let mut rng = SecureRng::new(OsRng);
/// let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
///
/// let rich_ciphertext_1 = IntegerElGamal::encrypt(&Integer::from(4), &public_key, &mut rng).enrich(&public_key);
/// let rich_ciphertext_2 = IntegerElGamal::encrypt(&Integer::from(6), &public_key, &mut rng).enrich(&public_key);
///
/// println!("[4] * [6] = [{}]", IntegerElGamal::decrypt(&(&rich_ciphertext_1 * &rich_ciphertext_2), &secret_key));
/// // Prints: "[4] * [6] = [24]".
/// ```
pub struct IntegerElGamal;

/// Public key containing the ElGamal encryption key and the modulus of the group.
pub struct IntegerElGamalPublicKey {
    pub(crate) h: Integer,
    pub(crate) modulus: Integer,
}

/// ElGamal ciphertext of integers.
pub struct IntegerElGamalCiphertext {
    pub(crate) c1: Integer,
    pub(crate) c2: Integer,
}

/// A struct holding both a ciphertext and a reference to its associated public key, which is
/// useful for decrypting directly using the secret key or performing homomorphic operations.
pub struct RichIntegerElGamalCiphertext<'pk> {
    /// The ciphertext to operate on
    pub ciphertext: IntegerElGamalCiphertext,
    /// Reference to the associated public key
    pub public_key: &'pk IntegerElGamalPublicKey,
}

impl<'pk> Enrichable<'pk, IntegerElGamalPublicKey, RichIntegerElGamalCiphertext<'pk>>
    for IntegerElGamalCiphertext
{
    fn enrich(self, public_key: &IntegerElGamalPublicKey) -> RichIntegerElGamalCiphertext
    where
        Self: Sized,
    {
        RichIntegerElGamalCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

impl AsymmetricCryptosystem<'_> for IntegerElGamal {
    type Plaintext = Integer;
    type Ciphertext = IntegerElGamalCiphertext;
    type RichCiphertext<'pk> = RichIntegerElGamalCiphertext<'pk>;
    type PublicKey = IntegerElGamalPublicKey;
    type SecretKey = Integer;

    /// Generates a fresh ElGamal keypair.
    /// ```
    /// # use scicrypt_traits::randomness::SecureRng;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rand_core::OsRng;
    /// # let mut rng = SecureRng::new(OsRng);
    /// let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// ```
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let modulus = gen_safe_prime(security_param.to_public_key_bit_length(), rng);

        let q = Integer::from(&modulus >> 1);
        let secret_key = q.random_below(&mut rng.rug_rng());
        let public_key = Integer::from(Integer::from(4).secure_pow_mod_ref(&secret_key, &modulus));

        (
            IntegerElGamalPublicKey {
                h: public_key,
                modulus,
            },
            secret_key,
        )
    }

    /// Encrypts an integer using the public key.
    /// ```
    /// # use scicrypt_traits::randomness::SecureRng;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rand_core::OsRng;
    /// # use rug::Integer;
    /// # let mut rng = SecureRng::new(OsRng);
    /// # let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// let ciphertext = IntegerElGamal::encrypt(&Integer::from(5), &public_key, &mut rng);
    /// ```
    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let q = Integer::from(&public_key.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        IntegerElGamalCiphertext {
            c1: Integer::from(Integer::from(4).secure_pow_mod_ref(&y, &public_key.modulus)),
            c2: (plaintext
                * Integer::from(public_key.h.secure_pow_mod_ref(&y, &public_key.modulus)))
            .rem(&public_key.modulus),
        }
    }

    /// Decrypts an ElGamal ciphertext using the secret key.
    /// ```
    /// # use scicrypt_traits::randomness::SecureRng;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use scicrypt_traits::Enrichable;
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = SecureRng::new(OsRng);
    /// # let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// # let ciphertext = IntegerElGamal::encrypt(&Integer::from(5), &public_key, &mut rng);
    /// let rich_ciphertext = ciphertext.enrich(&public_key);
    /// println!("The decrypted message is {}", IntegerElGamal::decrypt(&rich_ciphertext, &secret_key));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt(
        rich_ciphertext: &RichIntegerElGamalCiphertext,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext {
        (&rich_ciphertext.ciphertext.c2
            * Integer::from(
                rich_ciphertext
                    .ciphertext
                    .c1
                    .secure_pow_mod_ref(secret_key, &rich_ciphertext.public_key.modulus),
            )
            .invert(&rich_ciphertext.public_key.modulus)
            .unwrap())
        .rem(&rich_ciphertext.public_key.modulus)
    }
}

impl<'pk> Mul for &RichIntegerElGamalCiphertext<'pk> {
    type Output = RichIntegerElGamalCiphertext<'pk>;

    fn mul(self, rhs: Self) -> Self::Output {
        RichIntegerElGamalCiphertext {
            ciphertext: IntegerElGamalCiphertext {
                c1: Integer::from(&self.ciphertext.c1 * &rhs.ciphertext.c1)
                    .rem(&self.public_key.modulus),
                c2: Integer::from(&self.ciphertext.c2 * &rhs.ciphertext.c2)
                    .rem(&self.public_key.modulus),
            },
            public_key: self.public_key,
        }
    }
}

impl<'pk> RichIntegerElGamalCiphertext<'pk> {
    /// Computes the ciphertext corresponding to the plaintext raised to a scalar power.
    pub fn pow(&self, rhs: &Integer) -> RichIntegerElGamalCiphertext {
        RichIntegerElGamalCiphertext {
            ciphertext: IntegerElGamalCiphertext {
                c1: Integer::from(
                    self.ciphertext
                        .c1
                        .pow_mod_ref(rhs, &self.public_key.modulus)
                        .unwrap(),
                ),
                c2: Integer::from(
                    self.ciphertext
                        .c2
                        .pow_mod_ref(rhs, &self.public_key.modulus)
                        .unwrap(),
                ),
            },
            public_key: self.public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::integer_el_gamal::IntegerElGamal;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    use scicrypt_traits::randomness::SecureRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::Enrichable;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sk) =
            IntegerElGamal::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = IntegerElGamal::encrypt(&Integer::from(19), &pk, &mut rng);

        assert_eq!(
            Integer::from(19),
            IntegerElGamal::decrypt(&ciphertext.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sk) =
            IntegerElGamal::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = IntegerElGamal::encrypt(&Integer::from(7), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = &ciphertext * &ciphertext;

        assert_eq!(
            Integer::from(49),
            IntegerElGamal::decrypt(&ciphertext_twice, &sk)
        );
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sk) =
            IntegerElGamal::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = IntegerElGamal::encrypt(&Integer::from(9), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = ciphertext.pow(&Integer::from(4));

        assert_eq!(
            Integer::from(6561),
            IntegerElGamal::decrypt(&ciphertext_twice, &sk)
        );
    }
}
