use rug::Integer;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, PublicKey, SecretKey};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::ops::{Mul, Rem};

/// The RSA cryptosystem.
#[derive(Copy, Clone)]
pub struct Rsa {
    modulus_size: u32,
}

/// Public key for the RSA cryptosystem.
pub struct RsaPK {
    n: Integer,
    e: Integer,
}

pub struct RsaSK {
    d: Integer,
}

/// Ciphertext of the Paillier cryptosystem, which is multiplicatively homomorphic.
pub struct RsaCiphertext {
    c: Integer,
}

pub struct AssociatedRsaCiphertext<'pk> {
    ciphertext: RsaCiphertext,
    public_key: &'pk RsaPK,
}

impl RsaCiphertext {
    pub fn associate(self, public_key: &RsaPK) -> AssociatedRsaCiphertext {
        AssociatedRsaCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

impl AsymmetricCryptosystem<'_, RsaPK, RsaSK> for Rsa {
    fn setup(security_param: &BitsOfSecurity) -> Self {
        Rsa {
            modulus_size: security_param.to_public_key_bit_length(),
        }
    }

    fn generate_keys<R: SecureRng>(
        &self,
        rng: &mut GeneralRng<R>,
    ) -> (RsaPK, RsaSK) {
        let (n, lambda) = gen_rsa_modulus(self.modulus_size, rng);

        let e = Integer::from(65537);
        let d = Integer::from(e.invert_ref(&lambda).unwrap());

        (RsaPK { n, e }, RsaSK { d })
    }
}

impl PublicKey for RsaPK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedRsaCiphertext<'pk>;

    fn encrypt<IntoP: Into<Self::Plaintext>, R: SecureRng>(&self, plaintext: IntoP, _rng: &mut GeneralRng<R>) -> AssociatedRsaCiphertext {
        RsaCiphertext {
            c: Integer::from(plaintext.into().pow_mod_ref(&self.e, &self.n).unwrap()),
        }.associate(self)
    }
}

impl SecretKey<'_, RsaPK> for RsaSK {
    type Plaintext = Integer;
    type Ciphertext<'pk> = AssociatedRsaCiphertext<'pk>;

    fn decrypt(&self, associated_ciphertext: &AssociatedRsaCiphertext) -> Self::Plaintext {
        Integer::from(
            associated_ciphertext
                .ciphertext
                .c
                .secure_pow_mod_ref(&self.d, &associated_ciphertext.public_key.n),
        )
    }
}

impl<'pk> Mul for &AssociatedRsaCiphertext<'pk> {
    type Output = AssociatedRsaCiphertext<'pk>;

    fn mul(self, rhs: Self) -> Self::Output {
        AssociatedRsaCiphertext {
            ciphertext: RsaCiphertext {
                c: Integer::from(&self.ciphertext.c * &rhs.ciphertext.c).rem(&self.public_key.n),
            },
            public_key: self.public_key,
        }
    }
}

// TODO: Add later as trait and impl
// impl<'pk> RichRSACiphertext<'pk> {
//     /// Computes the ciphertext corresponding to the plaintext raised to a scalar power.
//     pub fn pow(&self, rhs: &Integer) -> RichRSACiphertext {
//         RichRSACiphertext {
//             ciphertext: RsaCiphertext {
//                 c: Integer::from(
//                     self.ciphertext
//                         .c
//                         .pow_mod_ref(rhs, &self.public_key.n)
//                         .unwrap(),
//                 ),
//             },
//             public_key: self.public_key,
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use crate::cryptosystems::rsa::Rsa;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = Rsa::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Rsa::encrypt(&Integer::from(15), &pk, &mut rng);

        assert_eq!(
            Integer::from(15),
            Rsa::decrypt(&ciphertext.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = Rsa::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Rsa::encrypt(&Integer::from(7), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = &ciphertext * &ciphertext;

        assert_eq!(Integer::from(49), Rsa::decrypt(&ciphertext_twice, &sk));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = Rsa::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);

        let ciphertext = Rsa::encrypt(&Integer::from(9), &pk, &mut rng).enrich(&pk);
        let ciphertext_twice = ciphertext.pow(&Integer::from(4));

        assert_eq!(Integer::from(6561), Rsa::decrypt(&ciphertext_twice, &sk));
    }
}
