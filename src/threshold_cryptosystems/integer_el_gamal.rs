use crate::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use crate::randomness::SecureRng;
use crate::{AsymmetricThresholdCryptosystem, DecryptionError, RichCiphertext};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rug::Integer;
use std::ops::Rem;
use crate::number_theory::gen_safe_prime;
use crate::cryptosystems::integer_el_gamal::{IntegerElGamal, IntegerElGamalCiphertext, IntegerElGamalPublicKey};

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
        let public_key = Integer::from(self.generator.secure_pow_mod_ref(&master_key, &self.modulus));

        (IntegerElGamalPublicKey { h: public_key, modulus: Integer::from(&self.modulus) }, partial_keys)
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
            Integer::from(rich_ciphertext.ciphertext.c1.secure_pow_mod_ref(&partial_key, &self.modulus)),
            Integer::from(&rich_ciphertext.ciphertext.c2),
        )
    }

    fn combine(
        &self,
        decryption_shares: &[Self::DecryptionShare],
        public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        Ok((Integer::from(&decryption_shares[0].1 * &decryption_shares.iter().map(|(a, _)| a).product::<Integer>().invert(&public_key.modulus).unwrap())).rem(&self.modulus))
    }
}

// pub struct TOfNIntegerElGamal {
//     threshold: u32,
//     key_count: u32,
// }
//
// pub struct TOfNIntegerElGamalPartialKey {
//     id: i32,
//     key: Scalar,
// }
//
// pub struct TOfNIntegerElGamalDecryptionShare {
//     id: i32,
//     c1: RistrettoPoint,
//     c2: RistrettoPoint,
// }
//
// impl AsymmetricThresholdCryptosystem for TOfNIntegerElGamal {
//     type Plaintext = RistrettoPoint;
//     type Ciphertext = CurveElGamalCiphertext;
//     type PublicKey = RistrettoPoint;
//     type PartialKey = TOfNIntegerElGamalPartialKey;
//     type DecryptionShare = TOfNIntegerElGamalDecryptionShare;
//
//     fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut SecureRng<R>) -> (Self::PublicKey, Vec<Self::PartialKey>) {
//         let master_key = Scalar::random(rng.rng());
//
//         let coefficients: Vec<Scalar> = (0..(self.threshold - 1))
//             .map(|_| Scalar::random(rng.rng()))
//             .collect();
//
//         let partial_keys: Vec<TOfNIntegerElGamalPartialKey> = (1..=self.key_count)
//             .map(|i| {
//                 let mut key = Scalar::from(master_key);
//
//                 for j in 0..(self.threshold - 1) {
//                     key += &coefficients[j as usize] * Scalar::from(i.pow(j + 1));
//                 }
//
//                 TOfNIntegerElGamalPartialKey {
//                     id: i as i32,
//                     key
//                 }
//             })
//             .collect();
//
//         (&master_key * &RISTRETTO_BASEPOINT_TABLE, partial_keys)
//     }
//
//     fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(&self, plaintext: &Self::Plaintext, public_key: &Self::PublicKey, rng: &mut SecureRng<R>) -> Self::Ciphertext {
//         let y = Scalar::random(rng.rng());
//
//         CurveElGamalCiphertext {
//             c1: &y * &RISTRETTO_BASEPOINT_TABLE,
//             c2: plaintext + y * public_key,
//         }
//     }
//
//     fn partially_decrypt<'pk>(&self, rich_ciphertext: &RichCiphertext<'pk, Self::Ciphertext, Self::PublicKey>, partial_key: &Self::PartialKey) -> Self::DecryptionShare {
//         TOfNIntegerElGamalDecryptionShare {
//             id: partial_key.id,
//             c1: &partial_key.key * rich_ciphertext.ciphertext.c1,
//             c2: rich_ciphertext.ciphertext.c2
//         }
//     }
//
//     fn combine(&self, decryption_shares: &[Self::DecryptionShare], _public_key: &Self::PublicKey) -> Result<Self::Plaintext, DecryptionError> {
//         let summed: RistrettoPoint = (0usize..(self.threshold as usize))
//             .zip(decryption_shares)
//             .map(|(i, share)| {
//                 let mut b = Scalar::one();
//
//                 for i_prime in 0usize..(self.threshold as usize) {
//                     if i == i_prime {
//                         continue;
//                     }
//
//                     if decryption_shares[i].id == decryption_shares[i_prime].id {
//                         continue;
//                     }
//
//                     b *= Scalar::from(decryption_shares[i_prime].id as u64);
//                     b *= (Scalar::from(decryption_shares[i_prime].id as u64) - Scalar::from(decryption_shares[i].id as u64)).invert();
//                 }
//
//                 &b * &share.c1
//             })
//             .sum::<RistrettoPoint>();
//
//         Ok(decryption_shares[0].c2 - summed)
//     }
// }

#[cfg(test)]
mod tests {
    use crate::randomness::SecureRng;
    use crate::{AsymmetricThresholdCryptosystem, Enrichable};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use crate::threshold_cryptosystems::integer_el_gamal::NOfNIntegerElGamal;
    use rug::Integer;

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

    // #[test]
    // fn test_encrypt_decrypt_2_of_3() {
    //     let mut rng = SecureRng::new(OsRng);
    //
    //     let t_of_n_curve_elgamal = TOfNCurveElGamal { threshold: 2, key_count: 3 };
    //     let (pk, sks) = t_of_n_curve_elgamal.generate_keys(&mut rng);
    //
    //     let plaintext = &Scalar::from(21u64) * &RISTRETTO_BASEPOINT_TABLE;
    //
    //     let ciphertext = t_of_n_curve_elgamal
    //         .encrypt(&plaintext, &pk, &mut rng)
    //         .enrich(&pk);
    //
    //     let share_1 = t_of_n_curve_elgamal.partially_decrypt(&ciphertext, &sks[0]);
    //     let share_3 = t_of_n_curve_elgamal.partially_decrypt(&ciphertext, &sks[2]);
    //
    //     assert_eq!(
    //         plaintext,
    //         t_of_n_curve_elgamal
    //             .combine(&vec![share_1, share_3], &pk)
    //             .unwrap()
    //     );
    // }
}
