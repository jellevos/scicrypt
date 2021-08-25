use crate::number_theory::{gen_coprime, gen_safe_prime};
use crate::randomness::SecureRng;
use crate::threshold_cryptosystems::AsymmetricTOfNCryptosystem;
use crate::{BitsOfSecurity, DecryptionError, Enrichable, RichCiphertext};
use rug::Integer;
use std::ops::Rem;

/// Threshold Paillier cryptosystem: Extension of Paillier that requires t out of n parties to
/// successfully decrypt.
pub struct ThresholdPaillier;

/// The public key for encryption.
pub struct ThresholdPaillierPublicKey {
    generator: Integer,
    modulus: Integer,
    theta: Integer,
    delta: Integer,
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct ThresholdPaillierPartialKey {
    id: i32,
    key: Integer,
}

/// A randomized ciphertext created using the public key.
pub struct ThresholdPaillierCiphertext {
    c: Integer,
}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct ThresholdPaillierDecryptionShare {
    id: i32,
    share: Integer,
}

impl Enrichable<ThresholdPaillierPublicKey> for ThresholdPaillierCiphertext {}

impl AsymmetricTOfNCryptosystem for ThresholdPaillier {
    type Plaintext = Integer;
    type Ciphertext = ThresholdPaillierCiphertext;
    type PublicKey = ThresholdPaillierPublicKey;
    type PartialKey = ThresholdPaillierPartialKey;
    type DecryptionShare = ThresholdPaillierDecryptionShare;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let prime_p = gen_safe_prime(security_param.to_public_key_bit_length() / 2, rng);
        let prime_q = gen_safe_prime(security_param.to_public_key_bit_length() / 2, rng);

        let subprime_p = Integer::from(&prime_p >> 1);
        let subprime_q = Integer::from(&prime_q >> 1);

        let modulus = Integer::from(&prime_p * &prime_q);
        let sub_modulus = Integer::from(&subprime_p * &subprime_q);

        let generator = Integer::from(&modulus + 1);

        let beta = gen_coprime(&modulus, rng);
        let theta = Integer::from(&sub_modulus * &beta).rem(&modulus);
        let delta = Integer::from(Integer::factorial(key_count_n as u32));

        let m_times_n = Integer::from(&sub_modulus * &modulus);
        let coefficients: Vec<Integer> = (0..(threshold_t - 1))
            .map(|_| Integer::from(m_times_n.random_below_ref(&mut rng.rug_rng())))
            .collect();

        let partial_keys: Vec<ThresholdPaillierPartialKey> = (1..=key_count_n)
            .map(|i| {
                let mut key = Integer::from(&beta * &sub_modulus);

                for j in 0..(threshold_t - 1) {
                    key += &coefficients[j as usize] * i.pow((j + 1) as u32) as u64;
                }

                ThresholdPaillierPartialKey {
                    id: i as i32,
                    key: key.rem(&m_times_n),
                }
            })
            .collect();

        (
            ThresholdPaillierPublicKey {
                generator,
                modulus,
                theta,
                delta,
            },
            partial_keys,
        )
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let n_squared = Integer::from(public_key.modulus.square_ref());
        let r = gen_coprime(&n_squared, rng);

        let first = Integer::from(
            public_key
                .generator
                .pow_mod_ref(plaintext, &n_squared)
                .unwrap(),
        );
        let second = r.secure_pow_mod(&public_key.modulus, &n_squared);

        ThresholdPaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }
    }

    fn partially_decrypt<'pk>(
        rich_ciphertext: &RichCiphertext<'pk, Self::Ciphertext, Self::PublicKey>,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        let n_squared = Integer::from(rich_ciphertext.public_key.modulus.square_ref());
        ThresholdPaillierDecryptionShare {
            id: partial_key.id,
            share: Integer::from(rich_ciphertext.ciphertext.c.secure_pow_mod_ref(
                &(Integer::from(2) * &rich_ciphertext.public_key.delta * &partial_key.key),
                &n_squared,
            )),
        }
    }

    fn combine(
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        let lambdas: Vec<Integer> = (0..decryption_shares.len())
            .map(|i| {
                let mut lambda = Integer::from(&public_key.delta);

                for i_prime in 0..decryption_shares.len() {
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
            })
            .collect();

        let n_squared = Integer::from(public_key.modulus.square_ref());

        let mut product = Integer::from(1);

        for (share, lambda) in decryption_shares.iter().zip(lambdas) {
            product = (product
                * Integer::from(
                    share
                        .share
                        .pow_mod_ref(&(Integer::from(2) * lambda), &n_squared)
                        .unwrap(),
                ))
            .rem(&n_squared);
        }

        let inverse =
            (Integer::from(4) * Integer::from(public_key.delta.square_ref()) * &public_key.theta)
                .invert(&public_key.modulus)
                .unwrap();

        Result::Ok(
            (((product - Integer::from(1)) / &public_key.modulus) * inverse)
                .rem(&public_key.modulus),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::randomness::SecureRng;
    use crate::threshold_cryptosystems::paillier::ThresholdPaillier;
    use crate::threshold_cryptosystems::AsymmetricTOfNCryptosystem;
    use crate::{BitsOfSecurity, Enrichable};
    use rand_core::OsRng;
    use rug::Integer;

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sks) = ThresholdPaillier::generate_keys(
            &BitsOfSecurity::Other { pk_bits: 160 },
            2,
            3,
            &mut rng,
        );

        let ciphertext = ThresholdPaillier::encrypt(&Integer::from(19), &pk, &mut rng).enrich(&pk);

        let share_1 = ThresholdPaillier::partially_decrypt(&ciphertext, &sks[0]);
        let share_3 = ThresholdPaillier::partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            Integer::from(19),
            ThresholdPaillier::combine(&vec![share_1, share_3], &pk).unwrap()
        );
    }
}
