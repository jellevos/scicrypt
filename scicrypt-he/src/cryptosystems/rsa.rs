use rug::Integer;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::Enrichable;
use std::ops::{Mul, Rem};

/// The RSA cryptosystem.
pub struct RSA;

/// Public key for the RSA cryptosystem.
pub struct RSAPublicKey {
    n: Integer,
    e: Integer,
}

/// Ciphertext of the Paillier cryptosystem, which is multiplicatively homomorphic.
pub struct RSACiphertext {
    c: Integer,
}

/// A struct holding both a ciphertext and a reference to its associated public key, which is
/// useful for decrypting directly using the secret key or performing homomorphic operations.
pub struct RichRSACiphertext<'pk> {
    /// The ciphertext to operate on
    ciphertext: RSACiphertext,
    /// Reference to the associated public key
    public_key: &'pk RSAPublicKey,
}

impl<'pk> Enrichable<'pk, RSAPublicKey, RichRSACiphertext<'pk>> for RSACiphertext {
    fn enrich(self, public_key: &RSAPublicKey) -> RichRSACiphertext
    where
        Self: Sized,
    {
        RichRSACiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

impl AsymmetricCryptosystem<'_> for RSA {
    type Plaintext = Integer;
    type Ciphertext = RSACiphertext;
    type RichCiphertext<'pk> = RichRSACiphertext<'pk>;

    type PublicKey = RSAPublicKey;
    type SecretKey = Integer;

    fn generate_keys<R: SecureRng>(
        security_param: &BitsOfSecurity,
        rng: &mut GeneralRng<R>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let (n, lambda) = gen_rsa_modulus(security_param.to_public_key_bit_length(), rng);

        let e = Integer::from(65537);
        let d = Integer::from(e.invert_ref(&lambda).unwrap());

        (RSAPublicKey { n, e }, d)
    }

    fn encrypt<R: SecureRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        _rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        RSACiphertext {
            c: Integer::from(plaintext.pow_mod_ref(&public_key.e, &public_key.n).unwrap()),
        }
    }

    fn decrypt(
        rich_ciphertext: &RichRSACiphertext,
        secret_key: &Self::SecretKey,
    ) -> Self::Plaintext {
        Integer::from(
            rich_ciphertext
                .ciphertext
                .c
                .secure_pow_mod_ref(secret_key, &rich_ciphertext.public_key.n),
        )
    }
}

impl<'pk> Mul for &RichRSACiphertext<'pk> {
    type Output = RichRSACiphertext<'pk>;

    fn mul(self, rhs: Self) -> Self::Output {
        RichRSACiphertext {
            ciphertext: RSACiphertext {
                c: Integer::from(&self.ciphertext.c * &rhs.ciphertext.c).rem(&self.public_key.n),
            },
            public_key: self.public_key,
        }
    }
}

impl<'pk> RichRSACiphertext<'pk> {
    /// Computes the ciphertext corresponding to the plaintext raised to a scalar power.
    pub fn pow(&self, rhs: &Integer) -> RichRSACiphertext {
        RichRSACiphertext {
            ciphertext: RSACiphertext {
                c: Integer::from(
                    self.ciphertext
                        .c
                        .pow_mod_ref(rhs, &self.public_key.n)
                        .unwrap(),
                ),
            },
            public_key: self.public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::rsa::RSA;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::Enrichable;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = RSA::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = RSA::encrypt(&Integer::from(15), &pk, &mut rng);

        assert_eq!(
            Integer::from(15),
            RSA::decrypt(&ciphertext.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = RSA::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = RSA::encrypt(&Integer::from(7), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = &ciphertext * &ciphertext;

        assert_eq!(Integer::from(49), RSA::decrypt(&ciphertext_twice, &sk));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = RSA::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = RSA::encrypt(&Integer::from(9), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = ciphertext.pow(&Integer::from(4));

        assert_eq!(Integer::from(6561), RSA::decrypt(&ciphertext_twice, &sk));
    }
}
