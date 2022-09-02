use scicrypt_bigint::BigInteger;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicAddition;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;

/// The Paillier cryptosystem.
#[derive(Copy, Clone)]
pub struct Paillier {
    modulus_size: u32,
}

/// Public key for the Paillier cryptosystem.
#[derive(PartialEq, Eq, Debug)]
pub struct PaillierPK {
    n: BigInteger,
    g: BigInteger,
}

/// Decryption key for the Paillier cryptosystem.
pub struct PaillierSK {
    lambda: BigInteger,
    mu: BigInteger,
}

/// Ciphertext of the Paillier cryptosystem, which is additively homomorphic.
pub struct PaillierCiphertext {
    pub(crate) c: BigInteger,
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
    /// let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
    /// let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// ```
    fn generate_keys<R: SecureRng>(&self, rng: &mut GeneralRng<R>) -> (PaillierPK, PaillierSK) {
        let (n, lambda) = gen_rsa_modulus(self.modulus_size, rng);

        let g = n.clone() + 1;
        let mu = (lambda.clone() % &n).invert(&n).unwrap();

        (PaillierPK { n, g }, PaillierSK { lambda, mu })
    }
}

impl EncryptionKey for PaillierPK {
    type Input = BigInteger;
    type Plaintext = BigInteger;
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
    /// # let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
    /// # let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
    /// ```
    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &BigInteger,
        rng: &mut GeneralRng<R>,
    ) -> PaillierCiphertext {
        let n_squared = self.n.square();
        let r = BigInteger::random_below(&n_squared, rng);

        let first = self.g.pow_mod(plaintext, &n_squared);
        let second = r.pow_mod(&self.n, &n_squared);

        PaillierCiphertext {
            c: (&first * &second) % &n_squared,
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
    /// # let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
    /// # let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// # let ciphertext = public_key.encrypt(&Integer::from(5), &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt_raw(&self, public_key: &PaillierPK, ciphertext: &PaillierCiphertext) -> BigInteger {
        let n_squared = public_key.n.square();

        let mut inner = ciphertext.c.pow_mod(&self.lambda, &n_squared);
        inner -= 1;
        inner = inner / &public_key.n;
        inner = &inner * &self.mu;

        inner % &public_key.n
    }
}

impl HomomorphicAddition for PaillierPK {
    fn add(
        &self,
        ciphertext_a: Self::Ciphertext,
        ciphertext_b: Self::Ciphertext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c) % &self.n.square(),
        }
    }

    fn mul(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext {
        let modulus = self.n.square();

        PaillierCiphertext {
            c: ciphertext.c.pow_mod(&input, &modulus),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::paillier::Paillier;
    use rand_core::OsRng;
    use scicrypt_bigint::BigInteger;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        println!("To encrypt");
        let ciphertext = pk.encrypt(&BigInteger::from(15u64), &mut rng);

        println!("To decrypt");
        println!("dec: {}", sk.decrypt(&ciphertext));
        assert_eq!(BigInteger::from(15u64), sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&BigInteger::from(7u64), &mut rng);
        let ciphertext_b = pk.encrypt(&BigInteger::from(7u64), &mut rng);
        let ciphertext_twice = ciphertext_a + ciphertext_b;

        assert_eq!(BigInteger::from(14u64), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&BigInteger::from(9u64), &mut rng);
        let ciphertext_twice = ciphertext * BigInteger::from(16u64);

        assert_eq!(BigInteger::from(144u64), sk.decrypt(&ciphertext_twice));
    }
}
