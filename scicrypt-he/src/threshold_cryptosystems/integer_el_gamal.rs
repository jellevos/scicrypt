use crate::cryptosystems::integer_el_gamal::{AssociatedIntegerElGamalCiphertext, IntegerElGamalCiphertext, IntegerElGamalPK};
use rug::Integer;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::{DecryptionShare, NOfNCryptosystem, TOfNCryptosystem};
use scicrypt_traits::DecryptionError;
use std::ops::Rem;
use scicrypt_traits::cryptosystems::{DecryptionKey};
use crate::constants::{SAFE_PRIME_1024, SAFE_PRIME_2048, SAFE_PRIME_3072};

/// N-out-of-N Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
#[derive(Clone)]
pub struct NOfNIntegerElGamal {
    modulus: Integer,
}

/// Decryption key for N-out-of-N Integer-based ElGamal
pub struct NOfNIntegerElGamalSK {
    key: Integer
}

impl NOfNCryptosystem<'_, IntegerElGamalPK, NOfNIntegerElGamalSK, NOfNIntegerElGamalShare> for NOfNIntegerElGamal {
    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        NOfNIntegerElGamal {
            modulus: Integer::from_str_radix(match security_param.to_public_key_bit_length() {
                1024 => SAFE_PRIME_1024,
                2048 => SAFE_PRIME_2048,
                3072 => SAFE_PRIME_3072,
                _ => panic!("No parameters available for this security parameter"),
            }, 16).unwrap(),
        }
    }

    fn generate_keys<R: SecureRng>(
        &self,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (IntegerElGamalPK, Vec<NOfNIntegerElGamalSK>) {
        let partial_keys: Vec<NOfNIntegerElGamalSK> = (0..key_count_n)
            .map(|_| NOfNIntegerElGamalSK { key: Integer::from(self.modulus.random_below_ref(&mut rng.rug_rng())) })
            .collect();

        let master_key: Integer = partial_keys.iter().map(|k| &k.key).sum();
        let public_key = Integer::from(Integer::from(4).secure_pow_mod_ref(&master_key, &self.modulus));

        (
            IntegerElGamalPK {
                h: public_key,
                modulus: Integer::from(&self.modulus),
            },
            partial_keys,
        )
    }
}

/// Decryption share of N-out-of-N integer-based ElGamal
pub struct NOfNIntegerElGamalShare(IntegerElGamalCiphertext);

impl DecryptionKey<'_, IntegerElGamalPK> for NOfNIntegerElGamalSK {
    type Plaintext = NOfNIntegerElGamalShare;
    type Ciphertext<'pk> = AssociatedIntegerElGamalCiphertext<'pk>;

    fn decrypt(&self, associated_ciphertext: &AssociatedIntegerElGamalCiphertext) -> Self::Plaintext {
        NOfNIntegerElGamalShare {
            0: IntegerElGamalCiphertext { c1: Integer::from(
                associated_ciphertext
                    .ciphertext
                    .c1
                    .secure_pow_mod_ref(&self.key, &associated_ciphertext.public_key.modulus),
            ), c2: Integer::from(&associated_ciphertext.ciphertext.c2), }
        }
    }
}

impl DecryptionShare for NOfNIntegerElGamalShare {
    type Plaintext = Integer;
    type PublicKey = IntegerElGamalPK;

    fn combine(decryption_shares: &[Self], public_key: &Self::PublicKey) -> Result<Self::Plaintext, DecryptionError> {
        Ok((Integer::from(
            &decryption_shares[0].0.c2
                * &decryption_shares
                .iter()
                .map(|share| &share.0.c1)
                .product::<Integer>()
                .invert(&public_key.modulus)
                .unwrap(),
        ))
            .rem(&public_key.modulus))
    }
}

/// Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires t out of n parties to
/// successfully decrypt.
#[derive(Clone)]
pub struct TOfNIntegerElGamal {
    modulus: Integer,
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct TOfNIntegerElGamalSK {
    pub(crate) id: i32,
    pub(crate) key: Integer,
}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct TOfNIntegerElGamalShare {
    id: i32,
    c1: Integer,
    c2: Integer,
}

impl TOfNCryptosystem<'_, IntegerElGamalPK, TOfNIntegerElGamalSK, TOfNIntegerElGamalShare> for TOfNIntegerElGamal {
    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        TOfNIntegerElGamal {
            modulus: Integer::from_str_radix(match security_param.to_public_key_bit_length() {
                1024 => SAFE_PRIME_1024,
                2048 => SAFE_PRIME_2048,
                3072 => SAFE_PRIME_3072,
                _ => panic!("No parameters available for this security parameter"),
            }, 16).unwrap(),
        }
    }

    fn generate_keys<R: SecureRng>(
        &self,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (IntegerElGamalPK, Vec<TOfNIntegerElGamalSK>) {
        let q = Integer::from(&self.modulus >> 1);
        let master_key = Integer::from(q.random_below_ref(&mut rng.rug_rng()));

        let coefficients: Vec<Integer> = (0..(threshold_t - 1))
            .map(|_| Integer::from(q.random_below_ref(&mut rng.rug_rng())))
            .collect();

        let partial_keys: Vec<TOfNIntegerElGamalSK> = (1..=key_count_n)
            .map(|i| {
                let mut key = Integer::from(&master_key);

                for j in 0..(threshold_t - 1) {
                    key = (key
                        + (&coefficients[j as usize] * Integer::from(i.pow((j + 1) as u32)))
                            .rem(&q))
                    .rem(&q);
                }

                TOfNIntegerElGamalSK { id: i as i32, key }
            })
            .collect();

        let public_key = Integer::from(Integer::from(4).secure_pow_mod_ref(&master_key, &self.modulus));

        (
            IntegerElGamalPK {
                h: public_key,
                modulus: Integer::from(&self.modulus),
            },
            partial_keys,
        )
    }
}

impl DecryptionKey<'_, IntegerElGamalPK> for TOfNIntegerElGamalSK {
    type Plaintext = TOfNIntegerElGamalShare;
    type Ciphertext<'pk> = AssociatedIntegerElGamalCiphertext<'pk>;

    fn decrypt(&self, associated_ciphertext: &AssociatedIntegerElGamalCiphertext) -> Self::Plaintext {
        TOfNIntegerElGamalShare {
            id: self.id,
            c1: Integer::from(
                associated_ciphertext
                    .ciphertext
                    .c1
                    .secure_pow_mod_ref(&self.key, &associated_ciphertext.public_key.modulus),
            ),
            c2: associated_ciphertext.ciphertext.c2.clone(),
        }
    }
}

impl DecryptionShare for TOfNIntegerElGamalShare {
    type Plaintext = Integer;
    type PublicKey = IntegerElGamalPK;

    fn combine(decryption_shares: &[Self], public_key: &Self::PublicKey) -> Result<Self::Plaintext, DecryptionError> {
        let q = Integer::from(&public_key.modulus >> 1);

        let multiplied: Integer = decryption_shares
            .iter()
            .enumerate()
            .map(|(i, share)| {
                let mut b = Integer::from(1);

                for i_prime in 0..decryption_shares.len() {
                    if i == i_prime {
                        continue;
                    }

                    if decryption_shares[i].id == decryption_shares[i_prime].id {
                        continue;
                    }

                    b = (b * Integer::from(decryption_shares[i_prime].id)).rem(&q);
                    b = (b
                        * (Integer::from(decryption_shares[i_prime].id)
                        - Integer::from(decryption_shares[i].id))
                        .invert(&q)
                        .unwrap())
                        .rem(&q);
                }

                Integer::from(share.c1.pow_mod_ref(&b, &public_key.modulus).unwrap())
            })
            .reduce(|a, b| (a * b).rem(&public_key.modulus))
            .unwrap();

        Ok(
            (&decryption_shares[0].c2 * multiplied.invert(&public_key.modulus).unwrap())
                .rem(&public_key.modulus),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::threshold_cryptosystems::integer_el_gamal::{NOfNIntegerElGamal, NOfNIntegerElGamalShare, TOfNIntegerElGamal, TOfNIntegerElGamalShare};
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::{EncryptionKey, DecryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::threshold_cryptosystems::{DecryptionShare, NOfNCryptosystem, TOfNCryptosystem};

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = NOfNIntegerElGamal::setup(&Default::default());
        let (pk, sks) = el_gamal.generate_keys(3, &mut rng);

        let plaintext = Integer::from(25);

        let ciphertext = pk.encrypt(Integer::from(&plaintext), &mut rng);

        let share_1 = sks[0].decrypt(&ciphertext);
        let share_2 = sks[1].decrypt(&ciphertext);
        let share_3 = sks[2].decrypt(&ciphertext);

        assert_eq!(
            plaintext,
            NOfNIntegerElGamalShare::combine(&[share_1, share_2, share_3], &pk).unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = TOfNIntegerElGamal::setup(&Default::default());
        let (pk, sks) = el_gamal.generate_keys(
            2,
            3,
            &mut rng,
        );

        let plaintext = Integer::from(2100u64);

        let ciphertext = pk.encrypt(Integer::from(&plaintext), &mut rng);

        let share_1 = sks[0].decrypt(&ciphertext);
        let share_3 = sks[2].decrypt(&ciphertext);

        assert_eq!(
            plaintext,
            TOfNIntegerElGamalShare::combine(&[share_1, share_3], &pk).unwrap()
        );
    }
}
