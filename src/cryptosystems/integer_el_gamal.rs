use crate::number_theory::gen_safe_prime;
use crate::randomness::SecureRng;
use crate::{AsymmetricCryptosystem, Enrichable, RichCiphertext};
use rug::Integer;
use std::ops::{Mul, Rem};

/// Multiplicatively homomorphic ElGamal over a safe prime group.
pub struct IntegerElGamal {
    modulus: Integer,
    generator: Integer,
}

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

impl IntegerElGamal {
    /// Creates a fresh `IntegerElGamal` instance over a randomly chosen safe prime group of size
    /// `group_size`.
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
        group_size: u32,
        rng: &mut SecureRng<R>,
    ) -> Self {
        let modulus = gen_safe_prime(group_size, rng);

        IntegerElGamal {
            modulus,
            generator: Integer::from(4),
        }
    }
}

impl Enrichable<IntegerElGamalPublicKey> for IntegerElGamalCiphertext {}

impl AsymmetricCryptosystem for IntegerElGamal {
    type Plaintext = Integer;
    type Ciphertext = IntegerElGamalCiphertext;
    type PublicKey = IntegerElGamalPublicKey;
    type SecretKey = Integer;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let q = Integer::from(&self.modulus >> 1);
        let secret_key = q.random_below(&mut rng.rug_rng());
        let public_key = Integer::from(
            self.generator
                .secure_pow_mod_ref(&secret_key, &self.modulus),
        );

        (
            IntegerElGamalPublicKey {
                h: public_key,
                modulus: Integer::from(&self.modulus),
            },
            secret_key,
        )
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let q = Integer::from(&public_key.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        IntegerElGamalCiphertext {
            c1: Integer::from(self.generator.secure_pow_mod_ref(&y, &public_key.modulus)),
            c2: (plaintext
                * Integer::from(public_key.h.secure_pow_mod_ref(&y, &public_key.modulus)))
            .rem(&public_key.modulus),
        }
    }

    fn decrypt(
        &self,
        rich_ciphertext: &RichCiphertext<Self::Ciphertext, Self::PublicKey>,
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

impl<'pk> Mul for &RichCiphertext<'pk, IntegerElGamalCiphertext, IntegerElGamalPublicKey> {
    type Output = RichCiphertext<'pk, IntegerElGamalCiphertext, IntegerElGamalPublicKey>;

    /// Homomorphic operation between two ElGamal ciphertexts.
    fn mul(self, rhs: Self) -> Self::Output {
        RichCiphertext {
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

impl<'pk> RichCiphertext<'pk, IntegerElGamalCiphertext, IntegerElGamalPublicKey> {
    /// Computes the ciphertext corresponding to the plaintext raised to a scalar power.
    pub fn pow(
        &self,
        rhs: &Integer,
    ) -> RichCiphertext<'pk, IntegerElGamalCiphertext, IntegerElGamalPublicKey> {
        RichCiphertext {
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
    use crate::randomness::SecureRng;
    use crate::AsymmetricCryptosystem;
    use crate::Enrichable;
    use rand_core::OsRng;
    use rug::Integer;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = SecureRng::new(OsRng);

        let el_gamal = IntegerElGamal::new(512, &mut rng);
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = el_gamal.encrypt(&Integer::from(19), &pk, &mut rng);

        assert_eq!(
            Integer::from(19),
            el_gamal.decrypt(&ciphertext.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = SecureRng::new(OsRng);

        let el_gamal = IntegerElGamal::new(512, &mut rng);
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = el_gamal
            .encrypt(&Integer::from(7), &pk, &mut rng)
            .enrich(&pk);
        let ciphertext_twice = &ciphertext * &ciphertext;

        assert_eq!(Integer::from(49), el_gamal.decrypt(&ciphertext_twice, &sk));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = SecureRng::new(OsRng);

        let el_gamal = IntegerElGamal::new(512, &mut rng);
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = el_gamal
            .encrypt(&Integer::from(9), &pk, &mut rng)
            .enrich(&pk);
        let ciphertext_twice = ciphertext.pow(&Integer::from(4));

        assert_eq!(
            Integer::from(6561),
            el_gamal.decrypt(&ciphertext_twice, &sk)
        );
    }
}
