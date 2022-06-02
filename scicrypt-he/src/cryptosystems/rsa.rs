use rug::Integer;
use scicrypt_numbertheory::bigint::BigInteger;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicMultiplication;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::ops::Rem;

/// The RSA cryptosystem.
#[derive(Copy, Clone)]
pub struct Rsa {
    modulus_size: u64,
}

/// Public key for the RSA cryptosystem.
#[derive(PartialEq, Debug)]
pub struct RsaPK {
    n: BigInteger,
    e: BigInteger,
}

/// Decryption key for RSA
pub struct RsaSK {
    d: BigInteger,
}

/// Ciphertext of the RSA cryptosystem, which is multiplicatively homomorphic.
pub struct RsaCiphertext {
    c: BigInteger,
}

impl Associable<RsaPK> for RsaCiphertext {}

impl AsymmetricCryptosystem for Rsa {
    type PublicKey = RsaPK;
    type SecretKey = RsaSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        Rsa {
            modulus_size: security_param.to_public_key_bit_length(),
        }
    }

    fn generate_keys<R: SecureRng>(&self, rng: &mut GeneralRng<R>) -> (RsaPK, RsaSK) {
        let (n, lambda) = gen_rsa_modulus(self.modulus_size, rng);

        let e = BigInteger::new(65537, 17);
        let d = e.clone().invert(&lambda).expect("e should always be invertible mod lambda.");

        (RsaPK { n, e }, RsaSK { d })
    }
}

impl EncryptionKey for RsaPK {
    type Input = BigInteger;
    type Plaintext = BigInteger;
    type Ciphertext = RsaCiphertext;

    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &BigInteger,
        _rng: &mut GeneralRng<R>,
    ) -> RsaCiphertext {
        RsaCiphertext {
            c: plaintext.pow_mod(&self.e, &self.n),
        }
    }
}

impl DecryptionKey<RsaPK> for RsaSK {
    fn decrypt_raw(&self, public_key: &RsaPK, ciphertext: &RsaCiphertext) -> BigInteger {
        ciphertext.c.pow_mod(&self.d, &public_key.n)
    }
}

impl HomomorphicMultiplication for RsaPK {
    fn mul(
        &self,
        ciphertext_a: Self::Ciphertext,
        ciphertext_b: Self::Ciphertext,
    ) -> Self::Ciphertext {
        let mut c = &ciphertext_a.c * &ciphertext_b.c;
        c %= &self.n;

        RsaCiphertext {
            c,
        }
    }

    fn pow(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext {        
        RsaCiphertext {
            c: ciphertext.c.pow_mod(&input, &self.n),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::rsa::Rsa;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_numbertheory::bigint::BigInteger;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&BigInteger::new(15, 160), &mut rng);

        assert_eq!(15, sk.decrypt(&ciphertext).get_u64());
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&BigInteger::new(7, 160), &mut rng);
        let ciphertext_b = pk.encrypt(&BigInteger::new(7, 160), &mut rng);
        let ciphertext_twice = ciphertext_a * ciphertext_b;

        assert_eq!(49, sk.decrypt(&ciphertext_twice).get_u64());
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&BigInteger::new(9, 160), &mut rng);
        let ciphertext_twice = ciphertext.pow(BigInteger::new(4, 160));

        assert_eq!(6561, sk.decrypt(&ciphertext_twice).get_u64());
    }
}
