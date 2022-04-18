use rug::Integer;
use scicrypt_numbertheory::{gen_coprime, gen_rsa_modulus};
//use scicrypt_traits::cryptosystems::{Associable, AssociatedCiphertext, AsymmetricCryptosystem, PublicKey, SecretKey};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::ops::{Add, Mul, Rem};
use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};

/// The Paillier cryptosystem.
#[derive(Copy, Clone)]
pub struct Paillier {
    modulus_size: u32,
}

/// Public key for the Paillier cryptosystem.
pub struct PaillierPK {
    n: Integer,
    g: Integer,
}

/// Decryption key for the Paillier cryptosystem.
pub struct PaillierSK {
    lambda: Integer,
    mu: Integer,
}

/// Ciphertext of the Paillier cryptosystem, which is additively homomorphic.
pub struct PaillierCiphertext {
    c: Integer,
}

/// Ciphertext of the Paillier cryptosystem, with an associated public key
pub struct AssociatedPaillierCiphertext<'pk> {
    ciphertext: PaillierCiphertext,
    public_key: &'pk PaillierPK,
}

impl PaillierCiphertext {  // Associable<PaillierPK, AssociatedPaillierCiphertext<'_>> for
    fn associate(self, public_key: &PaillierPK) -> AssociatedPaillierCiphertext {
        AssociatedPaillierCiphertext {
            ciphertext: self,
            public_key
        }
    }
}

impl AsymmetricCryptosystem<'_, PaillierPK, PaillierSK> for Paillier {
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
    fn generate_keys<R: SecureRng>(
        &self,
        rng: &mut GeneralRng<R>,
    ) -> (PaillierPK, PaillierSK) {
        let (n, lambda) = gen_rsa_modulus(self.modulus_size, rng);

        let g = &n + Integer::from(1);
        let mu = Integer::from(lambda.invert_ref(&n).unwrap());

        (PaillierPK { n, g }, PaillierSK { lambda, mu })
    }
}

impl EncryptionKey for PaillierPK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedPaillierCiphertext<'pk>;

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
    /// let ciphertext = public_key.encrypt(5, &mut rng);
    /// ```
    fn encrypt<IntoP: Into<Self::Plaintext>, R: SecureRng>(&self, plaintext: IntoP, rng: &mut GeneralRng<R>) -> AssociatedPaillierCiphertext {
        let n_squared = Integer::from(self.n.square_ref());
        let r = gen_coprime(&n_squared, rng);

        let first = Integer::from(self.g.pow_mod_ref(&plaintext.into(), &n_squared).unwrap());
        let second = r.secure_pow_mod(&self.n, &n_squared);

        PaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }.associate(self)
    }
}

impl DecryptionKey<'_, PaillierPK> for PaillierSK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedPaillierCiphertext<'pk>;

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
    /// # let ciphertext = public_key.encrypt(5, &mut rng);
    /// println!("The decrypted message is {}", secret_key.decrypt(&ciphertext));
    /// // Prints: "The decrypted message is 5".
    /// ```
    fn decrypt(&self, associated_ciphertext: &AssociatedPaillierCiphertext) -> Self::Plaintext {
        let n_squared = Integer::from(associated_ciphertext.public_key.n.square_ref());

        let mut inner = Integer::from(
            associated_ciphertext
                .ciphertext
                .c
                .secure_pow_mod_ref(&self.lambda, &n_squared),
        );
        inner -= 1;
        inner /= &associated_ciphertext.public_key.n;
        inner *= &self.mu;

        inner.rem(&associated_ciphertext.public_key.n)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'pk> Add for &AssociatedPaillierCiphertext<'pk> {
    type Output = AssociatedPaillierCiphertext<'pk>;

    fn add(self, rhs: Self) -> Self::Output {
        AssociatedPaillierCiphertext {
            ciphertext: PaillierCiphertext {
                c: Integer::from(&self.ciphertext.c * &rhs.ciphertext.c)
                    .rem(Integer::from(self.public_key.n.square_ref())),
            },
            public_key: self.public_key,
        }
    }
}

impl<'pk> Mul<&Integer> for &AssociatedPaillierCiphertext<'pk> {
    type Output = AssociatedPaillierCiphertext<'pk>;

    fn mul(self, rhs: &Integer) -> Self::Output {
        let modulus = Integer::from(self.public_key.n.square_ref());

        AssociatedPaillierCiphertext {
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
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, EncryptionKey, DecryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(15, &mut rng);

        assert_eq!(
            15,
            sk.decrypt(&ciphertext)
        );
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(7, &mut rng);
        let ciphertext_twice = &ciphertext + &ciphertext;

        assert_eq!(Integer::from(14), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = Paillier::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(9, &mut rng);
        let ciphertext_twice = &ciphertext * &Integer::from(16);

        assert_eq!(
            144,
            sk.decrypt(&ciphertext_twice)
        );
    }
}
