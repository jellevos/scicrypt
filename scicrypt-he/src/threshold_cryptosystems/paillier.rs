use rug::Integer;
use scicrypt_numbertheory::{gen_coprime, gen_safe_prime};
use scicrypt_traits::cryptosystems::{EncryptionKey, Associable};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::{DecryptionShare, TOfNCryptosystem, PartialDecryptionKey};
use scicrypt_traits::DecryptionError;
use std::ops::Rem;

/// Threshold Paillier cryptosystem: Extension of Paillier that requires t out of n parties to
/// successfully decrypt.
#[derive(Copy, Clone)]
pub struct ThresholdPaillier {
    modulus_size: u32,
}

/// The public key for encryption.
#[derive(PartialEq, Debug)]
pub struct ThresholdPaillierPK {
    generator: Integer,
    modulus: Integer,
    theta: Integer,
    delta: Integer,
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct ThresholdPaillierSK {
    id: i32,
    key: Integer,
}

/// A randomized ciphertext created using the public key.
pub struct ThresholdPaillierCiphertext {
    c: Integer,
}

impl Associable<ThresholdPaillierPK> for ThresholdPaillierCiphertext {}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct ThresholdPaillierShare {
    id: i32,
    share: Integer,
}

impl TOfNCryptosystem for ThresholdPaillier {
    type PublicKey = ThresholdPaillierPK;
    type SecretKey = ThresholdPaillierSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        ThresholdPaillier {
            modulus_size: security_param.to_public_key_bit_length(),
        }
    }

    fn generate_keys<R: SecureRng>(
        &self,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (ThresholdPaillierPK, Vec<ThresholdPaillierSK>) {
        let prime_p = gen_safe_prime(self.modulus_size / 2, rng);
        let prime_q = gen_safe_prime(self.modulus_size / 2, rng);

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

        let partial_keys: Vec<ThresholdPaillierSK> = (1..=key_count_n)
            .map(|i| {
                let mut key = Integer::from(&beta * &sub_modulus);

                for j in 0..(threshold_t - 1) {
                    key += &coefficients[j as usize] * i.pow((j + 1) as u32) as u64;
                }

                ThresholdPaillierSK {
                    id: i as i32,
                    key: key.rem(&m_times_n),
                }
            })
            .collect();

        (
            ThresholdPaillierPK {
                generator,
                modulus,
                theta,
                delta,
            },
            partial_keys,
        )
    }
}

impl EncryptionKey for ThresholdPaillierPK {
    type Input = Integer;
    type Plaintext = Integer;
    type Ciphertext = ThresholdPaillierCiphertext;

    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &Integer,
        rng: &mut GeneralRng<R>,
    ) -> ThresholdPaillierCiphertext
    where
        Self: Sized,
    {
        let n_squared = Integer::from(self.modulus.square_ref());
        let r = gen_coprime(&n_squared, rng);

        let first = Integer::from(
            self.generator
                .pow_mod_ref(&plaintext.into(), &n_squared)
                .unwrap(),
        );
        let second = r.secure_pow_mod(&self.modulus, &n_squared);

        ThresholdPaillierCiphertext {
            c: (first * second).rem(&n_squared),
        }
    }
}

impl PartialDecryptionKey<ThresholdPaillierPK> for ThresholdPaillierSK {
    type DecryptionShare = ThresholdPaillierShare;

    fn partial_decrypt_raw(
        &self,
        public_key: &ThresholdPaillierPK,
        ciphertext: &ThresholdPaillierCiphertext,
    ) -> ThresholdPaillierShare {
        let n_squared = Integer::from(public_key.modulus.square_ref());
        ThresholdPaillierShare {
            id: self.id,
            share: Integer::from(ciphertext.c.secure_pow_mod_ref(
                &(Integer::from(2) * &public_key.delta * &self.key),
                &n_squared,
            )),
        }
    }
}

impl DecryptionShare<ThresholdPaillierPK> for ThresholdPaillierShare {
    fn combine(
        decryption_shares: &[Self],
        public_key: &ThresholdPaillierPK,
    ) -> Result<Integer, DecryptionError> {
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

// TODO: Implement homomorphism / simply use standard PaillierCiphertexts

#[cfg(test)]
mod tests {
    use crate::threshold_cryptosystems::paillier::{ThresholdPaillier, ThresholdPaillierShare};
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::EncryptionKey;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::threshold_cryptosystems::{DecryptionShare, TOfNCryptosystem, PartialDecryptionKey};

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = ThresholdPaillier::setup(&BitsOfSecurity::Other { pk_bits: 160 });
        let (pk, sks) = paillier.generate_keys(2, 3, &mut rng);

        let ciphertext = pk.encrypt(&Integer::from(19), &mut rng);

        let share_1 = sks[0].partial_decrypt(&ciphertext);
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        assert_eq!(
            Integer::from(19),
            ThresholdPaillierShare::combine(&[share_1, share_3], &pk).unwrap()
        );
    }
}
