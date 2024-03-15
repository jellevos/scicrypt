//! Here is an example of how to generates a key pair and encrypt a plaintext integer using the Paillier public key.
//! ```
//! use scicrypt_traits::randomness::GeneralRng;
//! use scicrypt_he::cryptosystems::paillier::Paillier;
//! use scicrypt_traits::security::BitsOfSecurity;
//! use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey};
//! use scicrypt_bigint::UnsignedInteger;
//! use rand_core::OsRng;
//!
//! let mut rng = GeneralRng::new(OsRng);
//! let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
//! let (public_key, secret_key) = paillier.generate_keys(&mut rng);
//! let ciphertext = public_key.encrypt(&UnsignedInteger::from(5), &mut rng);
//! ```
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

// FIXME: Consider adding a Paillier cryptosystem with CustomGen (custom generator)

/// The Paillier cryptosystem.
#[derive(Copy, Clone)]
pub struct Paillier {
    modulus_size: u32,
}

/// A minimal version of the public key for Paillier, which can be expanded to be more computationally efficient.
pub struct MinimalPaillierPK {
    /// Public modulus n for encryption
    pub n: UnsignedInteger,
}

impl MinimalPaillierPK {
    /// Expands this minimal key by precomputing some values. The resulting public key is faster to use but takes slightly more space.
    pub fn expand(self) -> PaillierPK {
        let n_squared = self.n.square();

        PaillierPK {
            n: self.n,
            n_squared,
        }
    }
}

/// Public key for the Paillier cryptosystem.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PaillierPK {
    /// Public modulus n for encryption
    pub n: UnsignedInteger,
    /// The modulus squared, i.e. n^2
    pub n_squared: UnsignedInteger,
}

impl PaillierPK {
    /// Minimizes the public key so that only the essential information is kept. This is useful if the public key must be transmitted or stored somewhere.
    pub fn minimize(&self) -> MinimalPaillierPK {
        MinimalPaillierPK { n: self.n.clone() }
    }
}

/// Decryption key for the Paillier cryptosystem.
#[derive(Debug, Clone)]
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
        let (n, p, q) = gen_rsa_modulus(self.modulus_size, rng);

        // The generator g is implicit: n + 1

        let lambda = &(p - 1) * &(q - 1);
        let mu = lambda.clone().invert(&n).unwrap();

        (MinimalPaillierPK { n }.expand(), PaillierSK { lambda, mu })
    }
}

impl EncryptionKey for PaillierPK {
    type Input = UnsignedInteger;
    type Plaintext = UnsignedInteger;
    type Ciphertext = PaillierCiphertext;
    type Randomness = UnsignedInteger;

    fn encrypt_without_randomness(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        PaillierCiphertext {
            c: ((&self.n * &(self.n.clone() + plaintext)) + 1) % &self.n_squared,
            //c: (self.n.clone() + 1).pow_mod(plaintext, &self.n_squared),
        }
    }

    fn randomize<R: SecureRng>(
        &self,
        ciphertext: Self::Ciphertext,
        rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        // r must be coprime with n_squared but this only fails with probability 2^(1 - n_in_bits)
        // 0 also only occurs with extremely low probability, so we can simply sample randomly s.t. 0 < r < n
        let r = UnsignedInteger::random_below(&self.n, rng);

        self.randomize_with(ciphertext, &r)
    }

    fn randomize_with(
        &self,
        ciphertext: Self::Ciphertext,
        randomness: &Self::Randomness,
    ) -> Self::Ciphertext {
        let randomizer = randomness.pow_mod(&self.n, &self.n_squared);

        PaillierCiphertext {
            c: (&ciphertext.c * &randomizer) % &self.n_squared,
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
        let mut inner = ciphertext.c.pow_mod(&self.lambda, &public_key.n_squared);
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
            c: (&ciphertext_a.c * &ciphertext_b.c) % &self.n_squared,
        }
    }

    fn mul_constant(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        PaillierCiphertext {
            c: ciphertext.c.pow_mod(input, &self.n_squared),
        }
    }

    fn sub(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c.clone().invert(&self.n_squared).unwrap())
                % &self.n_squared,
        }
    }

    fn add_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: (&ciphertext.c * &((&self.n * constant + 1) % &self.n_squared)) % &self.n_squared,
        }
    }

    fn sub_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        // FIXME: We should not have to use `invert_leaky` here
        PaillierCiphertext {
            c: (&ciphertext.c
                * &((&self.n * constant + 1) % &self.n_squared)
                    .invert_leaky(&self.n_squared)
                    .unwrap())
                % &self.n_squared,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::paillier::Paillier;
    use rand_core::OsRng;
    use scicrypt_bigint::UnsignedInteger;
    use scicrypt_traits::cryptosystems::{
        Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
    };
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

        let ciphertext = pk.encrypt(&UnsignedInteger::zero(0), &mut rng);

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

    #[test]
    fn test_randomize() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt_raw(&UnsignedInteger::from(21), &mut rng);
        let ciphertext_randomized = pk.randomize(ciphertext.clone(), &mut rng);

        assert_ne!(ciphertext, ciphertext_randomized);

        assert_eq!(
            UnsignedInteger::from(21),
            sk.decrypt(&ciphertext_randomized.associate(&pk))
        );
    }
}
