use rug::Integer;
use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::ops::{Mul, Rem};
use crate::constants::{SAFE_PRIME_1024, SAFE_PRIME_2048, SAFE_PRIME_3072};

/// Multiplicatively homomorphic ElGamal over a safe prime group where the generator is 4.
///
/// As an example we compute the product between 4 and 6 using ElGamal's homomorphic property.
/// ```
/// # use scicrypt_traits::randomness::GeneralRng;
/// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
/// # use scicrypt_traits::security::BitsOfSecurity;
/// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
/// # use rand_core::OsRng;
/// # use rug::Integer;
/// let mut rng = GeneralRng::new(OsRng);
/// let el_gamal = IntegerElGamal::setup(&Default::default());
/// let (public_key, secret_key) = el_gamal.generate_keys(&mut rng);
///
/// let ciphertext_1 = public_key.encrypt(4, &mut rng);
/// let ciphertext_2 = public_key.encrypt(6, &mut rng);
///
/// println!("[4] * [6] = [{}]", secret_key.decrypt(&(&ciphertext_1 * &ciphertext_2)));
/// // Prints: "[4] * [6] = [24]".
/// ```
#[derive(Clone)]
pub struct IntegerElGamal {
    modulus: Integer,
}

/// Public key containing the ElGamal encryption key and the modulus of the group.
pub struct IntegerElGamalPK {
    pub(crate) h: Integer,
    pub(crate) modulus: Integer,
}

/// ElGamal ciphertext of integers.
pub struct IntegerElGamalCiphertext {
    pub(crate) c1: Integer,
    pub(crate) c2: Integer,
}

/// ElGamal ciphertext of integers, associated with a public key
pub struct AssociatedIntegerElGamalCiphertext<'pk> {
    pub(crate) ciphertext: IntegerElGamalCiphertext,
    pub(crate) public_key: &'pk IntegerElGamalPK,
}

impl IntegerElGamalCiphertext {  //Associable<IntegerElGamalPK, AssociatedIntegerElGamalCiphertext<'_>> for
    fn associate(self, public_key: &IntegerElGamalPK) -> AssociatedIntegerElGamalCiphertext {
        AssociatedIntegerElGamalCiphertext {
            ciphertext: self,
            public_key
        }
    }
}

/// Decryption key for Integer-based ElGamal
pub struct IntegerElGamalSK {
    pub(crate) key: Integer,
}

impl AsymmetricCryptosystem<'_, IntegerElGamalPK, IntegerElGamalSK> for IntegerElGamal {
    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        IntegerElGamal {
            modulus: Integer::from_str_radix(match security_param.to_public_key_bit_length() {
                1024 => SAFE_PRIME_1024,
                2048 => SAFE_PRIME_2048,
                3072 => SAFE_PRIME_3072,
                _ => panic!("No parameters available for this security parameter"),
            }, 16).unwrap(),
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
        let q = Integer::from(&self.modulus >> 1);
        let secret_key = q.random_below(&mut rng.rug_rng());
        let public_key = Integer::from(Integer::from(4).secure_pow_mod_ref(&secret_key, &self.modulus));

        (
            IntegerElGamalPK {
                h: public_key,
                modulus: Integer::from(&self.modulus),
            },
            IntegerElGamalSK { key: secret_key},
        )
    }
}

impl EncryptionKey for IntegerElGamalPK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedIntegerElGamalCiphertext<'pk>;

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
    /// let ciphertext = public_key.encrypt(5, &mut rng);
    /// ```
    fn encrypt<IntoP: Into<Self::Plaintext>, R: SecureRng>(&self, plaintext: IntoP, rng: &mut GeneralRng<R>) -> AssociatedIntegerElGamalCiphertext {
        let q = Integer::from(&self.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        IntegerElGamalCiphertext {
            c1: Integer::from(Integer::from(4).secure_pow_mod_ref(&y, &self.modulus)),
            c2: (plaintext.into()
                * Integer::from(self.h.secure_pow_mod_ref(&y, &self.modulus)))
                .rem(&self.modulus),
        }.associate(&self)
    }
}

impl DecryptionKey<'_, IntegerElGamalPK> for IntegerElGamalSK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedIntegerElGamalCiphertext<'pk>;

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
    /// # let ciphertext = public_key.encrypt(5, &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt(&self, associated_ciphertext: &AssociatedIntegerElGamalCiphertext) -> Self::Plaintext {
        (&associated_ciphertext.ciphertext.c2
            * Integer::from(
            associated_ciphertext
                .ciphertext
                .c1
                .secure_pow_mod_ref(&self.key, &associated_ciphertext.public_key.modulus),
        )
            .invert(&associated_ciphertext.public_key.modulus)
            .unwrap())
            .rem(&associated_ciphertext.public_key.modulus)
    }
}

impl<'pk> Mul for &AssociatedIntegerElGamalCiphertext<'pk> {
    type Output = AssociatedIntegerElGamalCiphertext<'pk>;

    fn mul(self, rhs: Self) -> Self::Output {
        AssociatedIntegerElGamalCiphertext {
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

impl<'pk> AssociatedIntegerElGamalCiphertext<'pk> {
    /// Computes the ciphertext corresponding to the plaintext raised to a scalar power.
    pub fn pow(&self, rhs: &Integer) -> AssociatedIntegerElGamalCiphertext {
        IntegerElGamalCiphertext {
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
        }.associate(self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::integer_el_gamal::IntegerElGamal;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(19, &mut rng);

        assert_eq!(
            19,
            sk.decrypt(&ciphertext)
        );
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(7, &mut rng);
        let ciphertext_twice = &ciphertext * &ciphertext;

        assert_eq!(
            49,
            sk.decrypt(&ciphertext_twice)
        );
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(9, &mut rng);
        let ciphertext_twice = ciphertext.pow(&Integer::from(4));

        assert_eq!(
            6561,
            sk.decrypt(&ciphertext_twice)
        );
    }
}
