use crate::cryptosystems::integer_el_gamal::{
    IntegerElGamalCiphertext, IntegerElGamalPublicKey, RichIntegerElGamalCiphertext,
};
use rug::Integer;
use scicrypt_numbertheory::gen_safe_prime;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::{
    AsymmetricNOfNCryptosystem, AsymmetricTOfNCryptosystem,
};
use scicrypt_traits::DecryptionError;
use std::ops::Rem;

/// N-out-of-N Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
pub struct NOfNIntegerElGamal;

impl AsymmetricNOfNCryptosystem for NOfNIntegerElGamal {
    type Plaintext = Integer;
    type Ciphertext = IntegerElGamalCiphertext;
    type RichCiphertext<'pk> = RichIntegerElGamalCiphertext<'pk>;
    type PublicKey = IntegerElGamalPublicKey;
    type PartialKey = Integer;
    type DecryptionShare = (Integer, Integer);

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        key_count_n: usize,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let modulus = gen_safe_prime(security_param.to_public_key_bit_length(), rng);

        let partial_keys: Vec<Integer> = (0..key_count_n)
            .map(|_| Integer::from(modulus.random_below_ref(&mut rng.rug_rng())))
            .collect();

        let master_key: Integer = partial_keys.iter().sum();
        let public_key = Integer::from(Integer::from(4).secure_pow_mod_ref(&master_key, &modulus));

        (
            IntegerElGamalPublicKey {
                h: public_key,
                modulus,
            },
            partial_keys,
        )
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let q = Integer::from(&public_key.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        IntegerElGamalCiphertext {
            c1: Integer::from(Integer::from(4).secure_pow_mod_ref(&y, &public_key.modulus)),
            c2: (plaintext
                * Integer::from(public_key.h.secure_pow_mod_ref(&y, &public_key.modulus)))
            .rem(&public_key.modulus),
        }
    }

    fn partially_decrypt(
        rich_ciphertext: &RichIntegerElGamalCiphertext,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        (
            Integer::from(
                rich_ciphertext
                    .ciphertext
                    .c1
                    .secure_pow_mod_ref(partial_key, &rich_ciphertext.public_key.modulus),
            ),
            Integer::from(&rich_ciphertext.ciphertext.c2),
        )
    }

    fn combine(
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        Ok((Integer::from(
            &decryption_shares[0].1
                * &decryption_shares
                    .iter()
                    .map(|(a, _)| a)
                    .product::<Integer>()
                    .invert(&public_key.modulus)
                    .unwrap(),
        ))
        .rem(&public_key.modulus))
    }
}

/// Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires t out of n parties to
/// successfully decrypt.
pub struct TOfNIntegerElGamal;

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct TOfNIntegerElGamalPartialKey {
    id: i32,
    key: Integer,
}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct TOfNIntegerElGamalDecryptionShare {
    id: i32,
    c1: Integer,
    c2: Integer,
}

impl AsymmetricTOfNCryptosystem for TOfNIntegerElGamal {
    type Plaintext = Integer;
    type Ciphertext = IntegerElGamalCiphertext;
    type RichCiphertext<'pk> = RichIntegerElGamalCiphertext<'pk>;
    type PublicKey = IntegerElGamalPublicKey;
    type PartialKey = TOfNIntegerElGamalPartialKey;
    type DecryptionShare = TOfNIntegerElGamalDecryptionShare;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let modulus = gen_safe_prime(security_param.to_public_key_bit_length(), rng);

        let q = Integer::from(&modulus >> 1);
        let master_key = Integer::from(q.random_below_ref(&mut rng.rug_rng()));

        let coefficients: Vec<Integer> = (0..(threshold_t - 1))
            .map(|_| Integer::from(q.random_below_ref(&mut rng.rug_rng())))
            .collect();

        let partial_keys: Vec<TOfNIntegerElGamalPartialKey> = (1..=key_count_n)
            .map(|i| {
                let mut key = Integer::from(&master_key);

                for j in 0..(threshold_t - 1) {
                    key = (key
                        + (&coefficients[j as usize] * Integer::from(i.pow((j + 1) as u32)))
                            .rem(&q))
                    .rem(&q);
                }

                TOfNIntegerElGamalPartialKey { id: i as i32, key }
            })
            .collect();

        let public_key = Integer::from(Integer::from(4).secure_pow_mod_ref(&master_key, &modulus));

        (
            IntegerElGamalPublicKey {
                h: public_key,
                modulus,
            },
            partial_keys,
        )
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let q = Integer::from(&public_key.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        IntegerElGamalCiphertext {
            c1: Integer::from(Integer::from(4).secure_pow_mod_ref(&y, &public_key.modulus)),
            c2: (plaintext
                * Integer::from(public_key.h.secure_pow_mod_ref(&y, &public_key.modulus)))
            .rem(&public_key.modulus),
        }
    }

    fn partially_decrypt(
        rich_ciphertext: &RichIntegerElGamalCiphertext,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        TOfNIntegerElGamalDecryptionShare {
            id: partial_key.id,
            c1: Integer::from(
                rich_ciphertext
                    .ciphertext
                    .c1
                    .secure_pow_mod_ref(&partial_key.key, &rich_ciphertext.public_key.modulus),
            ),
            c2: rich_ciphertext.ciphertext.c2.clone(),
        }
    }

    fn combine(
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
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
    use crate::threshold_cryptosystems::integer_el_gamal::{
        NOfNIntegerElGamal, TOfNIntegerElGamal,
    };
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::randomness::SecureRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::threshold_cryptosystems::{
        AsymmetricNOfNCryptosystem, AsymmetricTOfNCryptosystem,
    };
    use scicrypt_traits::Enrichable;

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sks) =
            NOfNIntegerElGamal::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, 3, &mut rng);

        let plaintext = Integer::from(25);

        let ciphertext = NOfNIntegerElGamal::encrypt(&plaintext, &pk, &mut rng).enrich(&pk);

        let share_1 = NOfNIntegerElGamal::partially_decrypt(&ciphertext, &sks[0]);
        let share_2 = NOfNIntegerElGamal::partially_decrypt(&ciphertext, &sks[1]);
        let share_3 = NOfNIntegerElGamal::partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            plaintext,
            NOfNIntegerElGamal::combine(&vec![share_1, share_2, share_3], &pk).unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sks) = TOfNIntegerElGamal::generate_keys(
            &BitsOfSecurity::Other { pk_bits: 160 },
            2,
            3,
            &mut rng,
        );

        let plaintext = Integer::from(2100u64);

        let ciphertext = TOfNIntegerElGamal::encrypt(&plaintext, &pk, &mut rng).enrich(&pk);

        let share_1 = TOfNIntegerElGamal::partially_decrypt(&ciphertext, &sks[0]);
        let share_3 = TOfNIntegerElGamal::partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            plaintext,
            TOfNIntegerElGamal::combine(&vec![share_1, share_3], &pk).unwrap()
        );
    }
}
