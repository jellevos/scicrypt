use crate::constants::{SAFE_PRIME_1024, SAFE_PRIME_2048, SAFE_PRIME_3072};
use rug::Integer;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicMultiplication;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use serde::{Deserialize, Serialize};
use std::ops::Rem;

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
/// let ciphertext_1 = public_key.encrypt(&Integer::from(4), &mut rng);
/// let ciphertext_2 = public_key.encrypt(&Integer::from(6), &mut rng);
///
/// println!("[4] * [6] = [{}]", secret_key.decrypt(&(&ciphertext_1 * &ciphertext_2)));
/// // Prints: "[4] * [6] = [24]".
/// ```
#[derive(Clone)]
pub struct IntegerElGamal {
    modulus: Integer,
}

/// Public key containing the ElGamal encryption key and the modulus of the group.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct IntegerElGamalPK {
    /// Generator for encrypting
    pub h: Integer,
    /// Modulus of public key
    pub modulus: Integer,
}

/// ElGamal ciphertext of integers.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct IntegerElGamalCiphertext {
    /// First part of ciphertext
    pub c1: Integer,
    /// Second part of ciphertext
    pub c2: Integer,
}

impl Associable<IntegerElGamalPK> for IntegerElGamalCiphertext {}

/// Decryption key for Integer-based ElGamal
pub struct IntegerElGamalSK {
    pub(crate) key: Integer,
}

impl AsymmetricCryptosystem for IntegerElGamal {
    type PublicKey = IntegerElGamalPK;
    type SecretKey = IntegerElGamalSK;

    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        IntegerElGamal {
            modulus: Integer::from_str_radix(
                match security_param.to_public_key_bit_length() {
                    1024 => SAFE_PRIME_1024,
                    2048 => SAFE_PRIME_2048,
                    3072 => SAFE_PRIME_3072,
                    _ => panic!("No parameters available for this security parameter"),
                },
                16,
            )
            .unwrap(),
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
        let public_key =
            Integer::from(Integer::from(4).secure_pow_mod_ref(&secret_key, &self.modulus));

        (
            IntegerElGamalPK {
                h: public_key,
                modulus: Integer::from(&self.modulus),
            },
            IntegerElGamalSK { key: secret_key },
        )
    }
}

impl EncryptionKey for IntegerElGamalPK {
    type Input = Integer;
    type Plaintext = Integer;
    type Ciphertext = IntegerElGamalCiphertext;
    type Randomness = Integer;

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

    fn encrypt_without_randomness(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: Integer::from(1),
            c2: plaintext.to_owned().rem(&self.modulus),
        }
    }

    fn randomize<R: SecureRng>(
        &self,
        ciphertext: Self::Ciphertext,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        let q = Integer::from(&self.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        self.randomize_with(ciphertext, &y)
    }

    fn randomize_with(
        &self,
        ciphertext: Self::Ciphertext,
        randomness: &Self::Randomness,
    ) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: Integer::from(Integer::from(4).secure_pow_mod_ref(randomness, &self.modulus)),
            c2: (ciphertext.c2
                * Integer::from(self.h.secure_pow_mod_ref(randomness, &self.modulus)))
            .rem(&self.modulus),
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
    ) -> Integer {
        (&ciphertext.c2
            * Integer::from(
                ciphertext
                    .c1
                    .secure_pow_mod_ref(&self.key, &public_key.modulus),
            )
            .invert(&public_key.modulus)
            .unwrap())
        .rem(&public_key.modulus)
    }

    fn decrypt_identity_raw(
        &self,
        public_key: &IntegerElGamalPK,
        ciphertext: &<IntegerElGamalPK as EncryptionKey>::Ciphertext,
    ) -> bool {
        ciphertext.c2
            == Integer::from(
                ciphertext
                    .c1
                    .secure_pow_mod_ref(&self.key, &public_key.modulus),
            )
    }
}

impl HomomorphicMultiplication for IntegerElGamalPK {
    fn mul(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: Integer::from(&ciphertext_a.c1 * &ciphertext_b.c1).rem(&self.modulus),
            c2: Integer::from(&ciphertext_a.c2 * &ciphertext_b.c2).rem(&self.modulus),
        }
    }

    fn pow(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        IntegerElGamalCiphertext {
            c1: Integer::from(ciphertext.c1.pow_mod_ref(input, &self.modulus).unwrap()),
            c2: Integer::from(ciphertext.c2.pow_mod_ref(input, &self.modulus).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::integer_el_gamal::IntegerElGamal;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(19), &mut rng);

        assert_eq!(19, sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_encrypt_decrypt_identity() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(1), &mut rng);

        assert!(sk.decrypt_identity(&ciphertext));
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_b = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_twice = &ciphertext_a * &ciphertext_b;

        assert_eq!(49, sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = IntegerElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(9), &mut rng);
        let ciphertext_twice = ciphertext.pow(&Integer::from(4));

        assert_eq!(6561, sk.decrypt(&ciphertext_twice));
    }
}
