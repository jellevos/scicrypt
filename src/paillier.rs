use crate::{AsymmetricCryptosystem, RichCiphertext, Enrichable};
use crate::randomness::SecureRng;
use rug::Integer;
use crate::number_theory::{gen_rsa_modulus, gen_coprime};
use std::ops::Rem;

struct Paillier {
    key_size: u32,
}

struct PaillierPublicKey {
    n: Integer,
    g: Integer,
}

struct PaillierCiphertext {
    c: Integer,
}

impl Enrichable<PaillierPublicKey> for PaillierCiphertext { }

impl AsymmetricCryptosystem for Paillier {
    type Plaintext = Integer;
    type Ciphertext = PaillierCiphertext;

    type PublicKey = PaillierPublicKey;
    type SecretKey = (Integer, Integer);

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut SecureRng<R>) -> (Self::PublicKey, Self::SecretKey) {
        let (n, lambda) = gen_rsa_modulus(self.key_size, rng);

        let g = &n + Integer::from(1);
        let mu = Integer::from(lambda.invert_ref(&n).unwrap());

        (PaillierPublicKey {
            n,
            g,
        }, (lambda, mu))
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(&self, plaintext: &Self::Plaintext, public_key: &Self::PublicKey, rng: &mut SecureRng<R>) -> Self::Ciphertext {
        let n_squared = Integer::from(public_key.n.square_ref());
        let r = gen_coprime(&n_squared, rng);

        let first = Integer::from(public_key.g.pow_mod_ref(&plaintext, &n_squared).unwrap());
        let second = r.secure_pow_mod(&public_key.n, &n_squared);

        PaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }
    }

    fn decrypt(&self, rich_ciphertext: &RichCiphertext<Self::Ciphertext, Self::PublicKey>, secret_key: &Self::SecretKey) -> Self::Plaintext {
        let (lambda, mu) = secret_key;
        let n_squared = Integer::from(rich_ciphertext.public_key.n.square_ref());

        let mut inner = Integer::from(rich_ciphertext.ciphertext.c.secure_pow_mod_ref(lambda, &n_squared));
        inner -= 1;
        inner /= &rich_ciphertext.public_key.n;
        inner *= mu;

        return inner.rem(&rich_ciphertext.public_key.n);
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use crate::randomness::SecureRng;
    use crate::{AsymmetricCryptosystem, Enrichable};
    use rug::Integer;
    use crate::paillier::Paillier;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = SecureRng::new(OsRng);

        let paillier = Paillier { key_size: 512 };
        let (pk, sk) = paillier.generate_keys(&mut rng);

        let ciphertext = paillier.encrypt(&Integer::from(15),
                                          &pk,
                                          &mut rng);

        assert_eq!(Integer::from(15), paillier.decrypt(&ciphertext.enrich(&pk), &sk));
    }

}
