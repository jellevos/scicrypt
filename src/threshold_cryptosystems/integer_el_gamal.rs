use crate::cryptosystems::integer_el_gamal::{IntegerElGamalCiphertext, IntegerElGamalPublicKey};
use crate::number_theory::gen_safe_prime;
use crate::randomness::SecureRng;
use crate::{AsymmetricThresholdCryptosystem, DecryptionError, RichCiphertext};
use rug::Integer;
use std::ops::Rem;

/// N-out-of-N Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
pub struct NOfNIntegerElGamal {
    modulus: Integer,
    generator: Integer,
    key_count: u32,
}

impl NOfNIntegerElGamal {
    /// Creates a fresh `NOfNIntegerElGamal` instance over a randomly chosen safe prime group of size
    /// `group_size`.
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
        group_size: u32,
        key_count: u32,
        rng: &mut SecureRng<R>,
    ) -> Self {
        let modulus = gen_safe_prime(group_size, rng);

        NOfNIntegerElGamal {
            modulus,
            generator: Integer::from(4),
            key_count,
        }
    }
}

impl AsymmetricThresholdCryptosystem for NOfNIntegerElGamal {
    type Plaintext = Integer;
    type Ciphertext = IntegerElGamalCiphertext;
    type PublicKey = IntegerElGamalPublicKey;
    type PartialKey = Integer;
    type DecryptionShare = (Integer, Integer);

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let partial_keys: Vec<Integer> = (0..self.key_count)
            .map(|_| Integer::from(self.modulus.random_below_ref(&mut rng.rug_rng())))
            .collect();

        let master_key: Integer = partial_keys.iter().sum();
        let public_key = Integer::from(
            self.generator
                .secure_pow_mod_ref(&master_key, &self.modulus),
        );

        (
            IntegerElGamalPublicKey {
                h: public_key,
                modulus: Integer::from(&self.modulus),
            },
            partial_keys,
        )
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let q = Integer::from(&public_key.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        IntegerElGamalCiphertext {
            c1: Integer::from(self.generator.secure_pow_mod_ref(&y, &public_key.modulus)),
            c2: (plaintext
                * Integer::from(public_key.h.secure_pow_mod_ref(&y, &public_key.modulus)))
            .rem(&public_key.modulus),
        }
    }

    fn partially_decrypt<'pk>(
        &self,
        rich_ciphertext: &RichCiphertext<'pk, Self::Ciphertext, Self::PublicKey>,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        (
            Integer::from(
                rich_ciphertext
                    .ciphertext
                    .c1
                    .secure_pow_mod_ref(partial_key, &self.modulus),
            ),
            Integer::from(&rich_ciphertext.ciphertext.c2),
        )
    }

    fn combine(
        &self,
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
        .rem(&self.modulus))
    }
}

/// Threshold ElGamal cryptosystem over integers: Extension of ElGamal that requires t out of n parties to
/// successfully decrypt.
pub struct TOfNIntegerElGamal {
    modulus: Integer,
    generator: Integer,
    threshold: u32,
    key_count: u32,
}

impl TOfNIntegerElGamal {
    /// Creates a fresh `TOfNIntegerElGamal` instance over a randomly chosen safe prime group of
    /// size `group_size`, with the given `threshold` T and `key_count` N.
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
        group_size: u32,
        threshold: u32,
        key_count: u32,
        rng: &mut SecureRng<R>,
    ) -> Self {
        let modulus = gen_safe_prime(group_size, rng);

        TOfNIntegerElGamal {
            modulus,
            generator: Integer::from(4),
            threshold,
            key_count,
        }
    }
}

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

impl AsymmetricThresholdCryptosystem for TOfNIntegerElGamal {
    type Plaintext = Integer;
    type Ciphertext = IntegerElGamalCiphertext;
    type PublicKey = IntegerElGamalPublicKey;
    type PartialKey = TOfNIntegerElGamalPartialKey;
    type DecryptionShare = TOfNIntegerElGamalDecryptionShare;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let q = Integer::from(&self.modulus >> 1);
        let master_key = Integer::from(q.random_below_ref(&mut rng.rug_rng()));

        let coefficients: Vec<Integer> = (0..(self.threshold - 1))
            .map(|_| Integer::from(q.random_below_ref(&mut rng.rug_rng())))
            .collect();

        let partial_keys: Vec<TOfNIntegerElGamalPartialKey> = (1..=self.key_count)
            .map(|i| {
                let mut key = Integer::from(&master_key);

                for j in 0..(self.threshold - 1) {
                    key = (key + (&coefficients[j as usize] * Integer::from(i.pow(j + 1))).rem(&q))
                        .rem(&q);
                }

                TOfNIntegerElGamalPartialKey { id: i as i32, key }
            })
            .collect();

        let public_key = Integer::from(
            self.generator
                .secure_pow_mod_ref(&master_key, &self.modulus),
        );

        (
            IntegerElGamalPublicKey {
                h: public_key,
                modulus: self.modulus.clone(),
            },
            partial_keys,
        )
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let q = Integer::from(&public_key.modulus >> 1);
        let y = q.random_below(&mut rng.rug_rng());

        IntegerElGamalCiphertext {
            c1: Integer::from(self.generator.secure_pow_mod_ref(&y, &public_key.modulus)),
            c2: (plaintext
                * Integer::from(public_key.h.secure_pow_mod_ref(&y, &public_key.modulus)))
            .rem(&public_key.modulus),
        }
    }

    fn partially_decrypt<'pk>(
        &self,
        rich_ciphertext: &RichCiphertext<'pk, Self::Ciphertext, Self::PublicKey>,
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
        &self,
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        let q = Integer::from(&self.modulus >> 1);

        let multiplied: Integer = (0usize..(self.threshold as usize))
            .zip(decryption_shares)
            .map(|(i, share)| {
                let mut b = Integer::from(1);

                for i_prime in 0usize..(self.threshold as usize) {
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
    use crate::randomness::SecureRng;
    use crate::threshold_cryptosystems::integer_el_gamal::{
        NOfNIntegerElGamal, TOfNIntegerElGamal,
    };
    use crate::{AsymmetricThresholdCryptosystem, Enrichable};
    use rand_core::OsRng;
    use rug::Integer;
    use std::ops::Rem;

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let n_of_n_curve_elgamal = NOfNIntegerElGamal::new(512, 3, &mut rng);
        let (pk, sks) = n_of_n_curve_elgamal.generate_keys(&mut rng);

        let plaintext = Integer::from(25);

        let ciphertext = n_of_n_curve_elgamal
            .encrypt(&plaintext, &pk, &mut rng)
            .enrich(&pk);

        let share_1 = n_of_n_curve_elgamal.partially_decrypt(&ciphertext, &sks[0]);
        let share_2 = n_of_n_curve_elgamal.partially_decrypt(&ciphertext, &sks[1]);
        let share_3 = n_of_n_curve_elgamal.partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            plaintext,
            n_of_n_curve_elgamal
                .combine(&vec![share_1, share_2, share_3], &pk)
                .unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let t_of_n_integer_elgamal = TOfNIntegerElGamal::new(512, 2, 3, &mut rng);
        let (pk, sks) = t_of_n_integer_elgamal.generate_keys(&mut rng);

        let plaintext = Integer::from(2100u64);

        let ciphertext = t_of_n_integer_elgamal
            .encrypt(&plaintext, &pk, &mut rng)
            .enrich(&pk);

        let share_1 = t_of_n_integer_elgamal.partially_decrypt(&ciphertext, &sks[0]);
        let share_3 = t_of_n_integer_elgamal.partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            plaintext,
            t_of_n_integer_elgamal
                .combine(&vec![share_1, share_3], &pk)
                .unwrap()
        );
    }
}
