use rug::Integer;
use scicrypt_bigint::UnsignedInteger;
use scicrypt_numbertheory::gen_safe_prime;
use scicrypt_traits::cryptosystems::{Associable, EncryptionKey};
use scicrypt_traits::homomorphic::HomomorphicAddition;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::{
    DecryptionShare, PartialDecryptionKey, TOfNCryptosystem,
};
use scicrypt_traits::DecryptionError;
use std::ops::Rem;

use crate::cryptosystems::paillier::PaillierCiphertext;

/// Threshold Paillier cryptosystem: Extension of Paillier that requires t out of n parties to
/// successfully decrypt.
#[derive(Copy, Clone)]
pub struct ThresholdPaillier {
    modulus_size: u32,
}

/// The public key for encryption.
#[derive(PartialEq, Eq, Debug)]
pub struct ThresholdPaillierPK {
    generator: UnsignedInteger,
    modulus: UnsignedInteger,
    theta: UnsignedInteger,
    delta: UnsignedInteger,
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct ThresholdPaillierSK {
    id: i32,
    key: UnsignedInteger,
}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct ThresholdPaillierShare {
    id: i32,
    share: UnsignedInteger,
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

        let subprime_p = &prime_p >> 1;
        let subprime_q = &prime_q >> 1;

        let modulus = &prime_p * &prime_q;
        let sub_modulus = &subprime_p * &subprime_q;

        let generator = modulus.clone() + 1;

        let beta = UnsignedInteger::random_below(&modulus, rng);
        let theta = (&sub_modulus * &beta) % &modulus;
        let delta = UnsignedInteger::factorial_leaky(key_count_n as u64);

        let m_times_n = &sub_modulus * &modulus;
        let coefficients: Vec<UnsignedInteger> = (0..(threshold_t - 1))
            .map(|_| UnsignedInteger::random_below(&m_times_n, rng))
            .collect();

        let partial_keys: Vec<ThresholdPaillierSK> = (1..=key_count_n)
            .map(|i| {
                let mut key = &beta * &sub_modulus;

                for j in 0..(threshold_t - 1) {
                    key += &((&coefficients[j as usize]
                        * &UnsignedInteger::from(i.pow((j + 1) as u32) as u64))
                        % &m_times_n);
                }

                ThresholdPaillierSK {
                    id: i as i32,
                    key: key % &m_times_n,
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

impl Associable<ThresholdPaillierPK> for PaillierCiphertext {}

impl EncryptionKey for ThresholdPaillierPK {
    type Input = UnsignedInteger;
    type Plaintext = UnsignedInteger;
    type Ciphertext = PaillierCiphertext;
    type Randomness = UnsignedInteger;

    fn encrypt_without_randomness(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        let n_squared = self.modulus.square();
        PaillierCiphertext {
            c: self.generator.pow_mod(plaintext, &n_squared),
        }
    }

    fn randomize<R: SecureRng>(
        &self,
        ciphertext: PaillierCiphertext,
        rng: &mut GeneralRng<R>,
    ) -> PaillierCiphertext
    where
        Self: Sized,
    {
        // r must be coprime with n_squared but this only fails with probability 2^(1 - n_in_bits)
        // 0 also only occurs with extremely low probability, so we can simply sample randomly s.t. 0 < r < n
        let r = UnsignedInteger::random_below(&self.modulus, rng);

        self.randomize_with(ciphertext, &r)
    }

    fn randomize_with(
        &self,
        ciphertext: Self::Ciphertext,
        randomness: &Self::Randomness,
    ) -> Self::Ciphertext {
        let n_squared = self.modulus.square();
        let randomizer = randomness.pow_mod(&self.modulus, &n_squared);

        PaillierCiphertext {
            c: (&ciphertext.c * &randomizer) % &n_squared,
        }
    }
}

impl HomomorphicAddition for ThresholdPaillierPK {
    fn add(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        PaillierCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c) % &self.modulus.square(),
        }
    }

    fn mul_constant(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        let modulus = self.modulus.square();

        PaillierCiphertext {
            c: ciphertext.c.pow_mod(input, &modulus),
        }
    }

    fn sub(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        let modulus = self.modulus.square();
        PaillierCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c.clone().invert(&modulus).unwrap()) % &modulus,
        }
    }

    fn add_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        let modulus = self.modulus.square();
        PaillierCiphertext {
            c: (&ciphertext.c * &self.generator.pow_mod(constant, &modulus)) % &modulus,
        }
    }

    fn sub_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        let modulus = self.modulus.square();
        PaillierCiphertext {
            c: (&ciphertext.c
                * &self
                    .generator
                    .pow_mod(constant, &modulus)
                    .invert(&modulus)
                    .unwrap())
                % &modulus,
        }
    }
}

impl PartialDecryptionKey<ThresholdPaillierPK> for ThresholdPaillierSK {
    type DecryptionShare = ThresholdPaillierShare;

    fn partial_decrypt_raw(
        &self,
        public_key: &ThresholdPaillierPK,
        ciphertext: &PaillierCiphertext,
    ) -> ThresholdPaillierShare {
        let n_squared = public_key.modulus.square();
        ThresholdPaillierShare {
            id: self.id,
            share: ciphertext.c.pow_mod(
                &(&(&UnsignedInteger::new(2, 2) * &public_key.delta) * &self.key),
                &n_squared,
            ),
        }
    }
}

impl DecryptionShare<ThresholdPaillierPK> for ThresholdPaillierShare {
    fn combine(
        decryption_shares: &[Self],
        public_key: &ThresholdPaillierPK,
    ) -> Result<UnsignedInteger, DecryptionError> {
        let lambdas: Vec<Integer> = (0..decryption_shares.len())
            .map(|i| {
                let mut lambda = public_key.delta.clone().to_rug();

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

        let n_squared = public_key.modulus.square();

        let mut product = UnsignedInteger::from(1u64);

        for (share, lambda) in decryption_shares.iter().zip(lambdas) {
            let lambda_is_negative = lambda < 0;

            let mut part = share
                .share
                .pow_mod(&(UnsignedInteger::from(lambda.abs() * 2u64)), &n_squared);

            if lambda_is_negative {
                part = part.invert(&n_squared).unwrap();
            }

            product = (&product * &part) % &n_squared;
        }

        let inverse = (&(&UnsignedInteger::from(4u64) * &public_key.delta.square())
            * &public_key.theta)
            .rem(&public_key.modulus)
            .invert(&public_key.modulus)
            .unwrap();

        product -= 1;

        Result::Ok((&(product / &public_key.modulus) * &inverse) % &public_key.modulus)
    }
}

#[cfg(test)]
mod tests {
    use crate::threshold_cryptosystems::paillier::{ThresholdPaillier, ThresholdPaillierShare};
    use rand_core::OsRng;
    use scicrypt_bigint::UnsignedInteger;
    use scicrypt_traits::cryptosystems::EncryptionKey;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::threshold_cryptosystems::{
        DecryptionShare, PartialDecryptionKey, TOfNCryptosystem,
    };

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let paillier = ThresholdPaillier::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sks) = paillier.generate_keys(2, 3, &mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(19u64), &mut rng);

        let share_1 = sks[0].partial_decrypt(&ciphertext);
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        assert_eq!(
            UnsignedInteger::from(19u64),
            ThresholdPaillierShare::combine(&[share_1, share_3], &pk).unwrap()
        );
    }
}
