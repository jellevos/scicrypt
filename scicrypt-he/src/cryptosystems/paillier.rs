use rug::Integer;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicAddition;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::ops::Rem;

/// The Paillier cryptosystem.
#[derive(Copy, Clone)]
pub struct Paillier {
    modulus_size: u32,
}

/// Public key for the Paillier cryptosystem.
#[derive(PartialEq, Debug)]
pub struct PaillierPK {
    n: Integer,
    n_squared: Integer,
    g: Integer,
}

/// Decryption key for the Paillier cryptosystem.
pub struct PaillierSK {
    lambda: Integer,
    mu: Integer,
}

/// Ciphertext of the Paillier cryptosystem, which is additively homomorphic.
pub struct PaillierCiphertext {
    pub(crate) c: Integer,
}

impl Associable<PaillierPK> for PaillierCiphertext {}

impl AsymmetricCryptosystem for Paillier {
    type PublicKey = PaillierPK;
    type SecretKey = PaillierSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        Paillier {
            modulus_size: security_param.to_public_key_bit_length(),
        }
    }

    /// Generates a fresh Paillier keypair.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    /// # use rand_core::OsRng;
    /// let mut rng = GeneralRng::new(OsRng);
    /// let paillier = Paillier::setup(&BitsOfSecurity::Other {pk_bits: 160});
    /// let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// ```
    fn generate_keys<R: SecureRng>(&self, rng: &mut GeneralRng<R>) -> (PaillierPK, PaillierSK) {
        let (n, lambda) = gen_rsa_modulus(self.modulus_size, rng);

        let g = &n + Integer::from(1);
        let mu = Integer::from(lambda.invert_ref(&n).unwrap());

        let n_squared = Integer::from(n.square_ref());

        (PaillierPK { n, g, n_squared }, PaillierSK { lambda, mu })
    }
}

impl EncryptionKey for PaillierPK {
    type Input = Integer;
    type Plaintext = Integer;
    type Ciphertext = PaillierCiphertext;

    /// Encrypts a plaintext integer using the Paillier public key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey};
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let paillier = Paillier::setup(&BitsOfSecurity::Other {pk_bits: 160});
    /// # let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
    /// ```
    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &Integer,
        rng: &mut GeneralRng<R>,
    ) -> PaillierCiphertext {
        // r must be coprime with n_squared but this only fails with probability 2^(1 - n_in_bits)
        // 0 also only occurs with extremely low probability, so we can simply sample randomly s.t. 0 < r < n
        let r = Integer::from(self.n.random_below_ref(&mut rng.rug_rng()));

        let first = Integer::from(self.g.pow_mod_ref(plaintext, &self.n_squared).unwrap());
        let second = r.secure_pow_mod(&self.n, &self.n_squared);

        PaillierCiphertext {
            c: (first * second).rem(&self.n_squared),
        }
    }
}

impl DecryptionKey<PaillierPK> for PaillierSK {
    /// Decrypts a rich Paillier ciphertext using the secret key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
    /// # use rug::Integer;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let paillier = Paillier::setup(&BitsOfSecurity::Other {pk_bits: 160});
    /// # let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// # let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt_raw(&self, public_key: &PaillierPK, ciphertext: &PaillierCiphertext) -> Integer {
        let n_squared = Integer::from(public_key.n.square_ref());

        let mut inner = Integer::from(ciphertext.c.secure_pow_mod_ref(&self.lambda, &n_squared));
        inner -= 1;
        inner /= &public_key.n;
        inner *= &self.mu;

        inner.rem(&public_key.n)
    }

    fn encrypt_fast_raw<R: SecureRng>(
        &self,
        public_key: &PaillierPK,
        plaintext: &<PaillierPK as EncryptionKey>::Plaintext,
        rng: &mut GeneralRng<R>,
    ) -> PaillierCiphertext {
        // r must be coprime with n_squared but this only fails with probability 2^(1 - n_in_bits)
        // 0 also only occurs with extremely low probability, so we can simply sample randomly s.t. 0 < r < n
        let r = Integer::from(public_key.n.random_below_ref(&mut rng.rug_rng()));

        let first = Integer::from(public_key.g.pow_mod_ref(plaintext, &public_key.n_squared).unwrap());
        let second = r.secure_pow_mod(&public_key.n, &public_key.n_squared);

        PaillierCiphertext {
            c: (first * second).rem(&public_key.n_squared),
        }
    }
}

impl HomomorphicAddition for PaillierPK {
    fn add(
        &self,
        ciphertext_a: Self::Ciphertext,
        ciphertext_b: Self::Ciphertext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: Integer::from(&ciphertext_a.c * &ciphertext_b.c)
                .rem(Integer::from(self.n.square_ref())),
        }
    }

    fn mul(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext {
        let modulus = Integer::from(self.n.square_ref());

        PaillierCiphertext {
            c: Integer::from(ciphertext.c.pow_mod_ref(&input, &modulus).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::paillier::Paillier;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(15), &mut rng);

        assert_eq!(15, sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_b = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_twice = ciphertext_a + ciphertext_b;

        assert_eq!(Integer::from(14), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(9), &mut rng);
        let ciphertext_twice = ciphertext * Integer::from(16);

        assert_eq!(144, sk.decrypt(&ciphertext_twice));
    }
}
