use crate::{AsymmetricThresholdCryptosystem, RichCiphertext, Enrichable};
use crate::randomness::SecureRng;
use crate::number_theory::{gen_safe_prime, gen_coprime};
use rug::Integer;
use std::ops::Rem;

struct ThresholdPaillier {
    key_size: u32,
    threshold: u32,
    key_count: u32,
}

struct ThresholdPaillierPublicKey {
    generator: Integer,
    modulus: Integer,
    theta: Integer,
    delta: Integer,
}

struct ThresholdPaillierPartialKey {
    id: i32,
    key: Integer,
}

struct ThresholdPaillierCiphertext {
    c: Integer,
}

struct ThresholdPaillierDecryptionShare {
    id: i32,
    share: Integer,
}

impl Enrichable<ThresholdPaillierPublicKey> for ThresholdPaillierCiphertext {}

impl AsymmetricThresholdCryptosystem for ThresholdPaillier {
    type Plaintext = Integer;
    type Ciphertext = ThresholdPaillierCiphertext;
    type PublicKey = ThresholdPaillierPublicKey;
    type PartialKey = ThresholdPaillierPartialKey;
    type DecryptionShare = ThresholdPaillierDecryptionShare;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut SecureRng<R>) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let p = gen_safe_prime(self.key_size / 2, rng);
        let q = gen_safe_prime(self.key_size / 2, rng);

        let pp = Integer::from(&p >> 1);
        let qq = Integer::from(&q >> 1);

        let n = Integer::from(&p * &q);
        let m = Integer::from(&pp * &qq);

        let g = Integer::from(&n + 1);

        let beta = gen_coprime(&n, rng);
        let theta = Integer::from(&m * &beta).rem(&n);
        let delta = Integer::from(Integer::factorial(self.key_count));

        let m_times_n = Integer::from(&m * &n);
        let coefficients: Vec<Integer> = (0..(self.threshold - 1))
            .map(|_| Integer::from(m_times_n.random_below_ref(&mut rng.rug_rng()))).collect();

        let partial_keys: Vec<ThresholdPaillierPartialKey> = (1..=self.key_count).map(|i| {
            let mut key = Integer::from(&beta * &m);

            for j in 0..(self.threshold - 1) {
                key += &coefficients[j as usize] * i.pow(j + 1);
            }

            ThresholdPaillierPartialKey {
                id: i as i32,
                key: key.rem(&m_times_n),
            }
        }).collect();

        return (ThresholdPaillierPublicKey {
            generator: g,
            modulus: n,
            theta,
            delta
        }, partial_keys)
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(&self, plaintext: &Self::Plaintext, public_key: &Self::PublicKey, rng: &mut SecureRng<R>) -> Self::Ciphertext {
        let n_squared = Integer::from(public_key.modulus.square_ref());
        let r = gen_coprime(&n_squared, rng);

        let first = Integer::from(public_key.generator.pow_mod_ref(plaintext, &n_squared).unwrap());
        let second = r.secure_pow_mod(&public_key.modulus, &n_squared);

        ThresholdPaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }
    }

    fn partially_decrypt<'pk>(&self, rich_ciphertext: &RichCiphertext<'pk, Self::Ciphertext, Self::PublicKey>, partial_key: &Self::PartialKey) -> Self::DecryptionShare {
        let n_squared = Integer::from(rich_ciphertext.public_key.modulus.square_ref());
        ThresholdPaillierDecryptionShare {
            id: partial_key.id,
            share: Integer::from(rich_ciphertext.ciphertext.c.secure_pow_mod_ref(&(Integer::from(2) * &rich_ciphertext.public_key.delta * &partial_key.key), &n_squared)),
        }
    }

    fn combine(&self, decryption_shares: &Vec<Self::DecryptionShare>, public_key: &Self::PublicKey) -> Result<Self::Plaintext, ()> {
        let lambdas: Vec<Integer> = (0usize..(self.threshold as usize)).map(|i| {
            let mut lambda = Integer::from(&public_key.delta);

            for i_prime in 0usize..(self.threshold as usize) {
                if i == i_prime {
                    continue;
                }

                if decryption_shares[i].id == decryption_shares[i_prime].id {
                    continue;
                }

                lambda *= decryption_shares[i_prime].id;
                lambda /= decryption_shares[i_prime].id - decryption_shares[i].id;
            }

            lambda
        }).collect();

        let n_squared = Integer::from(public_key.modulus.square_ref());

        let mut product = Integer::from(1);

        for (share, lambda) in decryption_shares.iter().zip(lambdas) {
            product = (product * Integer::from(share.share.pow_mod_ref(&(Integer::from(2) * lambda), &n_squared).unwrap()))
                .rem(&n_squared);
        }

        let inverse = (Integer::from(4) * Integer::from(public_key.delta.square_ref()) * &public_key.theta)
            .invert(&public_key.modulus).unwrap();

        Result::Ok((((product - Integer::from(1)) / &public_key.modulus) * inverse).rem(&public_key.modulus))
    }
}

#[cfg(test)]
mod tests {
    use crate::randomness::SecureRng;
    use rand_core::OsRng;
    use crate::threshold_cryptosystems::paillier::ThresholdPaillier;
    use crate::{AsymmetricThresholdCryptosystem, Enrichable};
    use rug::Integer;

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let thresh_paillier = ThresholdPaillier { key_size: 512, threshold: 2, key_count: 3 };
        let (pk, sks) = thresh_paillier.generate_keys(&mut rng);

        let ciphertext = thresh_paillier.encrypt(&Integer::from(19), &pk, &mut rng)
            .enrich(&pk);

        let share_1 = thresh_paillier.partially_decrypt(&ciphertext, &sks[0]);
        let share_3 = thresh_paillier.partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            Integer::from(19),
            thresh_paillier.combine(&vec![share_1, share_3], &pk).unwrap()
        );
    }

}
