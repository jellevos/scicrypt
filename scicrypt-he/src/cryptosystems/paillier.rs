use scicrypt_bigint::UnsignedInteger;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicAddition;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use serde::{Deserialize, Serialize};

/// The Paillier cryptosystem.
#[derive(Copy, Clone)]
pub struct Paillier {
    modulus_size: u32,
}

/// Public key for the Paillier cryptosystem.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PaillierPK {
    /// Public modulus n for encryption
    pub n: UnsignedInteger,
    /// Public generator g for encryption
    pub g: UnsignedInteger,
}
/// Decryption key for the Paillier cryptosystem.
pub struct PaillierSK {
    lambda: UnsignedInteger,
    mu: UnsignedInteger,
}

/// Ciphertext of the Paillier cryptosystem, which is additively homomorphic.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PaillierCiphertext {
    /// Encrypted message (Ciphertext)
    pub c: UnsignedInteger,
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
    type Input = UnsignedInteger;
    type Plaintext = UnsignedInteger;
    type Ciphertext = PaillierCiphertext;

    /// Encrypts a plaintext integer using the Paillier public key.
    /// ```
    /// # use scicrypt_traits::randomness::GeneralRng;
    /// # use scicrypt_he::cryptosystems::paillier::Paillier;
    /// # use scicrypt_traits::security::BitsOfSecurity;
    /// # use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey};
    /// # use scicrypt_bigint::UnsignedInteger;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
    /// # let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// let ciphertext = public_key.encrypt(&UnsignedInteger::from(5), &mut rng);
    /// ```
    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &UnsignedInteger,
        rng: &mut GeneralRng<R>,
    ) -> PaillierCiphertext {
        let n_squared = self.n.square();
        let r = UnsignedInteger::random_below(&n_squared, rng);

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
    /// # use scicrypt_bigint::UnsignedInteger;
    /// # use rand_core::OsRng;
    /// # let mut rng = GeneralRng::new(OsRng);
    /// # let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
    /// # let (public_key, secret_key) = paillier.generate_keys(&mut rng);
    /// # let ciphertext = public_key.encrypt(&UnsignedInteger::from(5), &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt_raw(
        &self,
        public_key: &PaillierPK,
        ciphertext: &PaillierCiphertext,
    ) -> UnsignedInteger {
        let n_squared = public_key.n.square();

        let mut inner = ciphertext.c.pow_mod(&self.lambda, &n_squared);
        inner -= 1;
        inner = inner / &public_key.n;
        inner = &inner * &self.mu;

        inner % &public_key.n
    }

    fn decrypt_identity_raw(
        &self,
        public_key: &PaillierPK,
        ciphertext: &<PaillierPK as EncryptionKey>::Ciphertext,
    ) -> bool {
        // TODO: This can be optimized
        self.decrypt_raw(public_key, ciphertext).is_zero_leaky()
    }
}

impl HomomorphicAddition for PaillierPK {
    fn add(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c) % &self.n.square(),
        }
    }

    fn mul_constant(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        let modulus = self.n.square();

        PaillierCiphertext {
            c: ciphertext.c.pow_mod(input, &modulus),
        }
    }

    fn sub(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        let modulus = self.n.square();
        PaillierCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c.clone().invert(&modulus).unwrap()) % &modulus,
        }
    }

    fn add_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        let modulus = self.n.square();
        PaillierCiphertext {
            c: (&ciphertext.c * &self.g.pow_mod(constant, &modulus)) % &modulus,
        }
    }

    fn sub_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        let modulus = self.n.square();
        PaillierCiphertext {
            c: (&ciphertext.c
                * &self
                    .g
                    .pow_mod(constant, &modulus)
                    .invert(&modulus)
                    .unwrap())
                % &modulus,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::paillier::Paillier;
    use rand_core::OsRng;
    use scicrypt_bigint::UnsignedInteger;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(15u64), &mut rng);

        assert_eq!(UnsignedInteger::from(15u64), sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_encrypt_decrypt_identity() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(0), &mut rng);

        assert!(sk.decrypt_identity(&ciphertext));
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_b = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_twice = &ciphertext_a + &ciphertext_b;

        assert_eq!(UnsignedInteger::from(14u64), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_sub() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&UnsignedInteger::from(7), &mut rng);
        let ciphertext_b = pk.encrypt(&UnsignedInteger::from(5), &mut rng);
        let ciphertext_res = &ciphertext_a - &ciphertext_b;

        assert_eq!(UnsignedInteger::from(2), sk.decrypt(&ciphertext_res));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(9u64), &mut rng);
        let ciphertext_twice = &ciphertext * &UnsignedInteger::from(16u64);

        assert_eq!(UnsignedInteger::from(144u64), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_add_constant() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(7), &mut rng);
        let ciphertext_res = &ciphertext + &UnsignedInteger::from(5);

        assert_eq!(UnsignedInteger::from(12), sk.decrypt(&ciphertext_res));
    }

    #[test]
    fn test_homomorphic_sub_constant() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(7), &mut rng);
        let ciphertext_res = &ciphertext - &UnsignedInteger::from(5);

        assert_eq!(UnsignedInteger::from(2), sk.decrypt(&ciphertext_res));
    }
}
