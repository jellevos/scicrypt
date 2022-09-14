use crate::constants::{SAFE_PRIME_1024, SAFE_PRIME_2048, SAFE_PRIME_3072};
use crate::cryptosystems::integer_el_gamal::{IntegerElGamalCiphertext, IntegerElGamalPK};
use rug::Integer;
use scicrypt_bigint::UnsignedInteger;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::{
    DecryptionShare, NOfNCryptosystem, PartialDecryptionKey, TOfNCryptosystem,
};
use scicrypt_traits::DecryptionError;
use std::ops::Rem;

/// N-out-of-N Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
#[derive(Clone)]
pub struct NOfNIntegerElGamal {
    modulus: UnsignedInteger,
}

/// Decryption key for N-out-of-N Integer-based ElGamal
pub struct NOfNIntegerElGamalSK {
    key: UnsignedInteger,
}

impl NOfNCryptosystem for NOfNIntegerElGamal {
    type PublicKey = IntegerElGamalPK;
    type SecretKey = NOfNIntegerElGamalSK;

    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        let public_key_len = security_param.to_public_key_bit_length();

        NOfNIntegerElGamal {
            modulus: UnsignedInteger::from_string_leaky(
                match public_key_len {
                    1024 => SAFE_PRIME_1024.to_string(),
                    2048 => SAFE_PRIME_2048.to_string(),
                    3072 => SAFE_PRIME_3072.to_string(),
                    _ => panic!("No parameters available for this security parameter"),
                },
                16,
                public_key_len,
            ),
        }
    }

    fn generate_keys<R: SecureRng>(
        &self,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (IntegerElGamalPK, Vec<NOfNIntegerElGamalSK>) {
        let q = &self.modulus >> 1;
        let partial_keys: Vec<NOfNIntegerElGamalSK> = (0..key_count_n)
            .map(|_| NOfNIntegerElGamalSK {
                key: UnsignedInteger::random_below(&q, rng),
            })
            .collect();

        let master_key: UnsignedInteger =
            partial_keys.iter().map(|k| &k.key).sum::<UnsignedInteger>() % &q;
        let public_key = UnsignedInteger::new(4, 3).pow_mod(&master_key, &self.modulus);

        (
            IntegerElGamalPK {
                h: public_key,
                modulus: self.modulus.clone(),
            },
            partial_keys,
        )
    }
}

/// Decryption share of N-out-of-N integer-based ElGamal
pub struct NOfNIntegerElGamalShare(IntegerElGamalCiphertext);

impl PartialDecryptionKey<IntegerElGamalPK> for NOfNIntegerElGamalSK {
    type DecryptionShare = NOfNIntegerElGamalShare;

    fn partial_decrypt_raw(
        &self,
        public_key: &IntegerElGamalPK,
        ciphertext: &IntegerElGamalCiphertext,
    ) -> NOfNIntegerElGamalShare {
        NOfNIntegerElGamalShare(IntegerElGamalCiphertext {
            c1: ciphertext.c1.pow_mod(&self.key, &public_key.modulus),
            c2: ciphertext.c2.clone(), // TODO: Now, all c2 are cloned. We only need one in decryption.
        })
    }
}

impl DecryptionShare<IntegerElGamalPK> for NOfNIntegerElGamalShare {
    fn combine(
        decryption_shares: &[Self],
        public_key: &IntegerElGamalPK,
    ) -> Result<UnsignedInteger, DecryptionError> {
        Ok((&decryption_shares[0].0.c2
            * &decryption_shares
                .iter()
                .map(|share| &share.0.c1)
                .product::<UnsignedInteger>() // TODO: We should probably keep reducing this value during aggregation
                .rem(&public_key.modulus)
                .invert(&public_key.modulus)
                .unwrap())
            % &public_key.modulus)
    } // FIXME: This fails randomly during tests
}

/// Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires t out of n parties to
/// successfully decrypt.
#[derive(Clone)]
pub struct TOfNIntegerElGamal {
    modulus: UnsignedInteger,
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct TOfNIntegerElGamalSK {
    pub(crate) id: i32,
    pub(crate) key: UnsignedInteger,
}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct TOfNIntegerElGamalShare {
    id: i32,
    c1: UnsignedInteger,
    c2: UnsignedInteger,
}

impl TOfNCryptosystem for TOfNIntegerElGamal {
    type PublicKey = IntegerElGamalPK;
    type SecretKey = TOfNIntegerElGamalSK;

    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        let public_key_len = security_param.to_public_key_bit_length();

        TOfNIntegerElGamal {
            modulus: UnsignedInteger::from_string_leaky(
                match public_key_len {
                    1024 => SAFE_PRIME_1024.to_string(),
                    2048 => SAFE_PRIME_2048.to_string(),
                    3072 => SAFE_PRIME_3072.to_string(),
                    _ => panic!("No parameters available for this security parameter"),
                },
                16,
                public_key_len,
            ),
        }
    }

    fn generate_keys<R: SecureRng>(
        &self,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (IntegerElGamalPK, Vec<TOfNIntegerElGamalSK>) {
        let q = &self.modulus >> 1;
        let master_key = UnsignedInteger::random_below(&q, rng);

        let coefficients: Vec<UnsignedInteger> = (0..(threshold_t - 1))
            .map(|_| UnsignedInteger::random_below(&q, rng))
            .collect();

        let partial_keys: Vec<TOfNIntegerElGamalSK> = (1..=key_count_n)
            .map(|i| {
                let mut key = master_key.clone();

                for j in 0..(threshold_t - 1) {
                    key = (key
                        + &((&coefficients[j as usize] * &UnsignedInteger::from(i.pow((j + 1) as u32) as u64))  // TODO: Can this be a u64 multiplication?
                            % &q))
                        % &q;
                }

                TOfNIntegerElGamalSK { id: i as i32, key }
            })
            .collect();

        let public_key = UnsignedInteger::new(4, 3).pow_mod(&master_key, &self.modulus);

        (
            IntegerElGamalPK {
                h: public_key,
                modulus: self.modulus.clone(),
            },
            partial_keys,
        )
    }
}

impl PartialDecryptionKey<IntegerElGamalPK> for TOfNIntegerElGamalSK {
    type DecryptionShare = TOfNIntegerElGamalShare;

    fn partial_decrypt_raw(
        &self,
        public_key: &IntegerElGamalPK,
        ciphertext: &IntegerElGamalCiphertext,
    ) -> TOfNIntegerElGamalShare {
        TOfNIntegerElGamalShare {
            id: self.id,
            c1: ciphertext.c1.pow_mod(&self.key, &public_key.modulus),
            c2: ciphertext.c2.clone(),
        }
    }
}

impl DecryptionShare<IntegerElGamalPK> for TOfNIntegerElGamalShare {
    fn combine(
        decryption_shares: &[Self],
        public_key: &IntegerElGamalPK,
    ) -> Result<UnsignedInteger, DecryptionError> {
        let q = (&public_key.modulus >> 1).to_rug();

        let multiplied: UnsignedInteger = decryption_shares
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

                share
                    .c1
                    .pow_mod(&UnsignedInteger::from(b), &public_key.modulus)
            })
            .reduce(|a, b| (&a * &b) % &public_key.modulus)
            .unwrap();

        Ok(
            (&decryption_shares[0].c2 * &multiplied.invert(&public_key.modulus).unwrap())
                % &public_key.modulus,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::threshold_cryptosystems::integer_el_gamal::{
        NOfNIntegerElGamal, NOfNIntegerElGamalShare, TOfNIntegerElGamal, TOfNIntegerElGamalShare,
    };
    use rand_core::OsRng;
    use scicrypt_bigint::UnsignedInteger;
    use scicrypt_traits::cryptosystems::EncryptionKey;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::threshold_cryptosystems::{
        DecryptionShare, NOfNCryptosystem, PartialDecryptionKey, TOfNCryptosystem,
    };

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = NOfNIntegerElGamal::setup(&Default::default());
        let (pk, sks) = el_gamal.generate_keys(3, &mut rng);

        let plaintext = UnsignedInteger::from(25u64);

        let ciphertext = pk.encrypt(&plaintext.clone(), &mut rng);

        let share_1 = sks[0].partial_decrypt(&ciphertext);
        let share_2 = sks[1].partial_decrypt(&ciphertext);
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        assert_eq!(
            plaintext,
            NOfNIntegerElGamalShare::combine(&[share_1, share_2, share_3], &pk).unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = TOfNIntegerElGamal::setup(&Default::default());
        let (pk, sks) = el_gamal.generate_keys(2, 3, &mut rng);

        let plaintext = UnsignedInteger::from(2100u64);

        let ciphertext = pk.encrypt(&plaintext, &mut rng);

        let share_1 = sks[0].partial_decrypt(&ciphertext);
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        assert_eq!(
            plaintext,
            TOfNIntegerElGamalShare::combine(&[share_1, share_3], &pk).unwrap()
        );
    }
}
