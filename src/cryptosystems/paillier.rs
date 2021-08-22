use crate::cryptosystems::AsymmetricCryptosystem;
use crate::number_theory::{gen_coprime, gen_rsa_modulus};
use crate::randomness::SecureRng;
use crate::{BitsOfSecurity, Enrichable, RichCiphertext};
use rug::Integer;
use std::ops::{Add, Mul, Rem};

/// The Paillier cryptosystem.
pub struct Paillier;

/// Public key for the Paillier cryptosystem.
pub struct PaillierPublicKey {
    n: Integer,
    g: Integer,
}

/// Ciphertext of the Paillier cryptosystem, which is additively homomorphic.
pub struct PaillierCiphertext {
    c: Integer,
}

impl Enrichable<PaillierPublicKey> for PaillierCiphertext {}

impl AsymmetricCryptosystem for Paillier {
    type Plaintext = Integer;
    type Ciphertext = PaillierCiphertext;

    type PublicKey = PaillierPublicKey;
    type SecretKey = (Integer, Integer);

    /// Generates a fresh Paillier keypair.
    /// ```
    /// # use scicrypt::cryptosystems::paillier::Paillier;
    /// # use scicrypt::randomness::SecureRng;
    /// # use rand_core::OsRng;
    /// # use scicrypt::cryptosystems::AsymmetricCryptosystem;
    /// # use scicrypt::BitsOfSecurity;
    /// #
    /// let mut rng = SecureRng::new(OsRng);
    /// let (public_key, secret_key) = Paillier::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// ```
    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let (n, lambda) = gen_rsa_modulus(security_param.to_public_key_bit_length(), rng);

        let g = &n + Integer::from(1);
        let mu = Integer::from(lambda.invert_ref(&n).unwrap());

        (PaillierPublicKey { n, g }, (lambda, mu))
    }

    /// Encrypts a plaintext integer using the Paillier public key.
    /// ```
    /// # use scicrypt::cryptosystems::paillier::Paillier;
    /// # use scicrypt::randomness::SecureRng;
    /// # use rand_core::OsRng;
    /// # use rug::Integer;
    /// # use scicrypt::cryptosystems::AsymmetricCryptosystem;
    /// # use scicrypt::BitsOfSecurity;
    /// #
    /// # let mut rng = SecureRng::new(OsRng);
    /// # let (public_key, secret_key) = Paillier::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// let ciphertext = Paillier::encrypt(&Integer::from(5), &public_key, &mut rng);
    /// ```
    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let n_squared = Integer::from(public_key.n.square_ref());
        let r = gen_coprime(&n_squared, rng);

        let first = Integer::from(public_key.g.pow_mod_ref(plaintext, &n_squared).unwrap());
        let second = r.secure_pow_mod(&public_key.n, &n_squared);

        PaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }
    }

    /// Decrypts a rich Paillier ciphertext using the secret key.
    /// ```
    /// # use scicrypt::cryptosystems::paillier::Paillier;
    /// # use scicrypt::randomness::SecureRng;
    /// # use rand_core::OsRng;
    /// # use rug::Integer;
    /// # use scicrypt::cryptosystems::AsymmetricCryptosystem;
    /// # use scicrypt::{Enrichable, BitsOfSecurity};
    /// #
    /// # let mut rng = SecureRng::new(OsRng);
    /// # let (public_key, secret_key) = Paillier::generate_keys(&BitsOfSecurity::Other {pk_bits: 160}, &mut rng);
    /// # let ciphertext = Paillier::encrypt(&Integer::from(5), &public_key, &mut rng);
    /// let rich_ciphertext = ciphertext.enrich(&public_key);
    /// println!("The decrypted message is {}", Paillier::decrypt(&rich_ciphertext, &secret_key));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt(
        rich_ciphertext: &RichCiphertext<Self::Ciphertext, Self::PublicKey>,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext {
        let (lambda, mu) = secret_key;
        let n_squared = Integer::from(rich_ciphertext.public_key.n.square_ref());

        let mut inner = Integer::from(
            rich_ciphertext
                .ciphertext
                .c
                .secure_pow_mod_ref(lambda, &n_squared),
        );
        inner -= 1;
        inner /= &rich_ciphertext.public_key.n;
        inner *= mu;

        inner.rem(&rich_ciphertext.public_key.n)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'pk> Add for &RichCiphertext<'pk, PaillierCiphertext, PaillierPublicKey> {
    type Output = RichCiphertext<'pk, PaillierCiphertext, PaillierPublicKey>;

    fn add(self, rhs: Self) -> Self::Output {
        RichCiphertext {
            ciphertext: PaillierCiphertext {
                c: Integer::from(&self.ciphertext.c * &rhs.ciphertext.c)
                    .rem(Integer::from(self.public_key.n.square_ref())),
            },
            public_key: self.public_key,
        }
    }
}

impl<'pk> Mul<&Integer> for &RichCiphertext<'pk, PaillierCiphertext, PaillierPublicKey> {
    type Output = RichCiphertext<'pk, PaillierCiphertext, PaillierPublicKey>;

    fn mul(self, rhs: &Integer) -> Self::Output {
        let modulus = Integer::from(self.public_key.n.square_ref());

        RichCiphertext {
            ciphertext: PaillierCiphertext {
                c: Integer::from(self.ciphertext.c.pow_mod_ref(rhs, &modulus).unwrap()),
            },
            public_key: self.public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::paillier::Paillier;
    use crate::cryptosystems::AsymmetricCryptosystem;
    use crate::randomness::SecureRng;
    use crate::{BitsOfSecurity, Enrichable};
    use rand_core::OsRng;
    use rug::Integer;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sk) = Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Paillier::encrypt(&Integer::from(15), &pk, &mut rng);

        assert_eq!(
            Integer::from(15),
            Paillier::decrypt(&ciphertext.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sk) = Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Paillier::encrypt(&Integer::from(7), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = &ciphertext + &ciphertext;

        assert_eq!(Integer::from(14), Paillier::decrypt(&ciphertext_twice, &sk));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sk) = Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Paillier::encrypt(&Integer::from(9), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = &ciphertext * &Integer::from(16);

        assert_eq!(
            Integer::from(144),
            Paillier::decrypt(&ciphertext_twice, &sk)
        );
    }
}
