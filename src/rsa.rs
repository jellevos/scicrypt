use crate::{AsymmetricCryptosystem, RichCiphertext, Enrichable};
use crate::randomness::SecureRng;
use rug::Integer;
use crate::number_theory::gen_safe_prime;
use std::ops::{Mul, Rem};

pub struct RSA {
    key_size: u32,
}

pub struct RSAPublicKey {
    n: Integer,
    e: Integer,
}

pub struct RSACiphertext {
    c: Integer,
}

impl Enrichable<RSAPublicKey> for RSACiphertext { }

impl AsymmetricCryptosystem for RSA {
    type Plaintext = Integer;
    type Ciphertext = RSACiphertext;
    type PublicKey = RSAPublicKey;
    type SecretKey = Integer;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut SecureRng<R>)
        -> (Self::PublicKey, Self::SecretKey) {
        let p = gen_safe_prime(self.key_size / 2, rng);
        let q = gen_safe_prime(self.key_size / 2, rng);

        let n = Integer::from(&p * &q);

        let lambda: Integer = (p - Integer::from(1)).lcm(&(q - Integer::from(1)));

        let e = Integer::from(65537);
        let d = Integer::from(e.invert_ref(&lambda).unwrap());

        return (RSAPublicKey { n, e }, d);
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(&self, plaintext: &Self::Plaintext,
                                                             public_key: &Self::PublicKey,
                                                             _rng: &mut SecureRng<R>) -> Self::Ciphertext {
        RSACiphertext {
            c: Integer::from(plaintext.pow_mod_ref(&public_key.e, &public_key.n)
                .unwrap())
        }
    }

    fn decrypt(&self, rich_ciphertext: &RichCiphertext<Self::Ciphertext, Self::PublicKey>,
                  secret_key: &Self::SecretKey) -> Self::Plaintext {
        Integer::from(
            rich_ciphertext.ciphertext.c
                .secure_pow_mod_ref(&secret_key, &rich_ciphertext.public_key.n)
        )
    }
}

impl<'pk> Mul for RichCiphertext<'pk, Integer, RSAPublicKey> {
    type Output = RichCiphertext<'pk, Integer, RSAPublicKey>;

    fn mul(self, rhs: Self) -> Self::Output {
        RichCiphertext {
            ciphertext: (self.ciphertext * rhs.ciphertext).rem(&self.public_key.n),
            public_key: self.public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use crate::randomness::SecureRng;
    use crate::{AsymmetricCryptosystem, Enrichable};
    use crate::rsa::RSA;
    use rug::Integer;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = SecureRng::new(OsRng);

        let rsa = RSA { key_size: 512 };
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = rsa.encrypt(&Integer::from(15),
                                               &pk,
                                               &mut rng);

        assert_eq!(Integer::from(15), rsa.decrypt(&ciphertext.enrich(&pk), &sk));
    }

}
