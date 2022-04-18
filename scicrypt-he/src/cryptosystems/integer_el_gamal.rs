use rug::Integer;
use scicrypt_numbertheory::gen_safe_prime;
use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, PublicKey, SecretKey};
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
/// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
/// # use scicrypt_traits::Enrichable;
/// # use rand_core::OsRng;
/// # use rug::Integer;
/// let mut rng = GeneralRng::new(OsRng);
/// let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
///
/// let rich_ciphertext_1 = IntegerElGamal::encrypt(&Integer::from(4), &public_key, &mut rng).enrich(&public_key);
/// let rich_ciphertext_2 = IntegerElGamal::encrypt(&Integer::from(6), &public_key, &mut rng).enrich(&public_key);
///
/// println!("[4] * [6] = [{}]", IntegerElGamal::decrypt(&(&rich_ciphertext_1 * &rich_ciphertext_2), &secret_key));
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
    /// let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
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

impl PublicKey for IntegerElGamalPK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedIntegerElGamalCiphertext<'pk>;

    /// Encrypts an integer using the public key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rand_core::OsRng;
    /// # use rug::Integer;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// let ciphertext = IntegerElGamal::encrypt(&Integer::from(5), &public_key, &mut rng);
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

impl SecretKey<'_, IntegerElGamalPK> for IntegerElGamalSK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedIntegerElGamalCiphertext<'pk>;

    /// Decrypts an ElGamal ciphertext using the secret key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::integer_el_gamal::IntegerElGamal;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use scicrypt_traits::Enrichable;
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let (public_key, secret_key) = IntegerElGamal::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// # let ciphertext = IntegerElGamal::encrypt(&Integer::from(5), &public_key, &mut rng);
    /// let rich_ciphertext = ciphertext.enrich(&public_key);
    /// println!("The decrypted message is {}", IntegerElGamal::decrypt(&rich_ciphertext, &secret_key));
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

// TODO: Replace with trait and impl
// impl<'pk> AssociatedCiphertext<'pk, IntegerElGamalPK, IntegerElGamalCiphertext> {
//     /// Computes the ciphertext corresponding to the plaintext raised to a scalar power.
//     pub fn pow(&self, rhs: &Integer) -> RichIntegerElGamalCiphertext {
//         RichIntegerElGamalCiphertext {
//             ciphertext: IntegerElGamalCiphertext {
//                 c1: Integer::from(
//                     self.ciphertext
//                         .c1
//                         .pow_mod_ref(rhs, &self.public_key.modulus)
//                         .unwrap(),
//                 ),
//                 c2: Integer::from(
//                     self.ciphertext
//                         .c2
//                         .pow_mod_ref(rhs, &self.public_key.modulus)
//                         .unwrap(),
//                 ),
//             },
//             public_key: self.public_key,
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use crate::cryptosystems::integer_el_gamal::IntegerElGamal;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

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
        let mut rng = GeneralRng::new(OsRng);

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
        let mut rng = GeneralRng::new(OsRng);

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
