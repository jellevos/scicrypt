use crate::constants::{SAFE_PRIME_1024, SAFE_PRIME_2048, SAFE_PRIME_3072};
use crate::cryptosystems::integer_el_gamal::{IntegerElGamalCiphertext, IntegerElGamalPK};
use scicrypt_bigint::BigInteger;
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
    modulus: BigInteger,
}

/// Decryption key for N-out-of-N Integer-based ElGamal
pub struct NOfNIntegerElGamalSK {
    key: BigInteger,
}

impl NOfNCryptosystem for NOfNIntegerElGamal {
    type PublicKey = IntegerElGamalPK;
    type SecretKey = NOfNIntegerElGamalSK;

    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        let public_key_len = security_param.to_public_key_bit_length();

        NOfNIntegerElGamal {
            modulus: BigInteger::from_string(
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
        let partial_keys: Vec<NOfNIntegerElGamalSK> = (0..key_count_n)
            .map(|_| NOfNIntegerElGamalSK {
                key: BigInteger::random_below(&self.modulus, rng),
            })
            .collect();

        let q = &self.modulus >> 1;
        let master_key: BigInteger = partial_keys.iter().map(|k| &k.key).sum::<BigInteger>() % &q;
        let public_key = BigInteger::new(4, 3).pow_mod(&master_key, &self.modulus);

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
    ) -> Result<BigInteger, DecryptionError> {
        Ok((&decryption_shares[0].0.c2
            * &decryption_shares
                .iter()
                .map(|share| &share.0.c1)
                .product::<BigInteger>() // TODO: We should probably keep reducing this value during aggregation
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
    modulus: BigInteger,
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct TOfNIntegerElGamalSK {
    pub(crate) id: i32,
    pub(crate) key: BigInteger,
}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct TOfNIntegerElGamalShare {
    id: i32,
    c1: BigInteger,
    c2: BigInteger,
}

impl TOfNCryptosystem for TOfNIntegerElGamal {
    type PublicKey = IntegerElGamalPK;
    type SecretKey = TOfNIntegerElGamalSK;

    /// Uses previously randomly generated safe primes as the modulus for pre-set modulus sizes.
    fn setup(security_param: &BitsOfSecurity) -> Self {
        let public_key_len = security_param.to_public_key_bit_length();

        TOfNIntegerElGamal {
            modulus: BigInteger::from_string(
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
        let master_key = BigInteger::random_below(&q, rng);

        let coefficients: Vec<BigInteger> = (0..(threshold_t - 1))
            .map(|_| BigInteger::random_below(&q, rng))
            .collect();

        let partial_keys: Vec<TOfNIntegerElGamalSK> = (1..=key_count_n)
            .map(|i| {
                let mut key = master_key.clone();

                for j in 0..(threshold_t - 1) {
                    key = (key
                        + &((&coefficients[j as usize] * &BigInteger::from(i.pow((j + 1) as u32) as u64))  // TODO: Can this be a u64 multiplication?
                            % &q))
                        % &q;
                }

                TOfNIntegerElGamalSK { id: i as i32, key }
            })
            .collect();

        let public_key = BigInteger::new(4, 3).pow_mod(&master_key, &self.modulus);

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
    ) -> Result<BigInteger, DecryptionError> {
        let q = &public_key.modulus >> 1;

        let multiplied: BigInteger = decryption_shares
            .iter()
            .enumerate()
            .map(|(i, share)| {
                let mut b = BigInteger::from(1u64);

                for i_prime in 0..decryption_shares.len() {
                    if i == i_prime {
                        continue;
                    }

                    if decryption_shares[i].id == decryption_shares[i_prime].id {
                        continue;
                    }

                    println!("GOING OVER {} {}", i, i_prime);

                    dbg!(&b);
                    dbg!(BigInteger::from(decryption_shares[i_prime].id as u64));
                    dbg!(&q);
                    dbg!(&b * &BigInteger::from(decryption_shares[i_prime].id as u64));
                    //dbg!((&b * &BigInteger::new(decryption_shares[i_prime].id as u64, q.size_in_bits())) % &q);
                    b = (&b * &BigInteger::from(decryption_shares[i_prime].id as u64)) % &q;
                    b = (&b
                        * &(BigInteger::from(decryption_shares[i_prime].id as u64)
                            - &BigInteger::from(decryption_shares[i].id as u64)))
                        .rem(&q)
                        .invert_unsecure(&q)
                        //.invert(&q)
                        .unwrap();
                    println!("NEXT");
                }

                share.c1.pow_mod(&b, &public_key.modulus)
            })
            .reduce(|a, b| (&a * &b) % &public_key.modulus)
            .unwrap();

        println!("GOING TO OK");
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
    use scicrypt_bigint::BigInteger;
    use scicrypt_traits::cryptosystems::EncryptionKey;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::threshold_cryptosystems::{
        DecryptionShare, NOfNCryptosystem, PartialDecryptionKey, TOfNCryptosystem,
    };

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        println!("setup");
        let el_gamal = NOfNIntegerElGamal::setup(&Default::default());
        println!("generate keys");
        let (pk, sks) = el_gamal.generate_keys(3, &mut rng);

        let plaintext = BigInteger::from(25u64);

        println!("encrypt");
        let ciphertext = pk.encrypt(&plaintext.clone(), &mut rng);

        println!("partial decrypt 1");
        let share_1 = sks[0].partial_decrypt(&ciphertext);
        println!("partial decrypt 2");
        let share_2 = sks[1].partial_decrypt(&ciphertext);
        println!("partial decrypt 3");
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        println!("combine");
        assert_eq!(
            plaintext,
            NOfNIntegerElGamalShare::combine(&[share_1, share_2, share_3], &pk).unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        println!("setup");
        let el_gamal = TOfNIntegerElGamal::setup(&Default::default());
        println!("generate keys");
        let (pk, sks) = el_gamal.generate_keys(2, 3, &mut rng);

        let plaintext = BigInteger::from(2100u64);

        println!("encrypt");
        let ciphertext = pk.encrypt(&plaintext, &mut rng);

        println!("partial decrypt 1");
        let share_1 = sks[0].partial_decrypt(&ciphertext);
        println!("partial decrypt 2");
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        println!("combine");
        assert_eq!(
            plaintext,
            TOfNIntegerElGamalShare::combine(&[share_1, share_3], &pk).unwrap()
        );
    }
}
