use crate::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use crate::randomness::SecureRng;
use crate::{AsymmetricThresholdCryptosystem, DecryptionError, RichCiphertext};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// N-out-of-N Threshold ElGamal cryptosystem over elliptic curves: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
pub struct NOfNCurveElGamal {
    /// The number of keys N
    pub key_count: u32,
}

impl AsymmetricThresholdCryptosystem for NOfNCurveElGamal {
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;
    type PublicKey = RistrettoPoint;
    type PartialKey = Scalar;
    type DecryptionShare = (RistrettoPoint, RistrettoPoint);

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let partial_keys: Vec<Scalar> = (0..self.key_count)
            .map(|_| Scalar::random(rng.rng()))
            .collect();

        let master_key: Scalar = partial_keys.iter().sum();
        let public_key = &master_key * &RISTRETTO_BASEPOINT_TABLE;

        (public_key, partial_keys)
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let y = Scalar::random(rng.rng());

        CurveElGamalCiphertext {
            c1: &y * &RISTRETTO_BASEPOINT_TABLE,
            c2: plaintext + y * public_key,
        }
    }

    fn partially_decrypt<'pk>(
        &self,
        rich_ciphertext: &RichCiphertext<'pk, Self::Ciphertext, Self::PublicKey>,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        (
            partial_key * rich_ciphertext.ciphertext.c1,
            rich_ciphertext.ciphertext.c2,
        )
    }

    #[allow(clippy::op_ref)]
    fn combine(
        &self,
        decryption_shares: &[Self::DecryptionShare],
        _public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        Ok(decryption_shares[0].1 - &decryption_shares.iter().map(|(a, _)| a).sum())
    }
}

/// Threshold ElGamal cryptosystem over elliptic curves: Extension of ElGamal that requires t out of n parties to
/// successfully decrypt.
pub struct TOfNCurveElGamal {
    threshold: u32,
    key_count: u32,
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct TOfNCurveElGamalPartialKey {
    id: i32,
    key: Scalar,
}

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct TOfNCurveElGamalDecryptionShare {
    id: i32,
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

impl AsymmetricThresholdCryptosystem for TOfNCurveElGamal {
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;
    type PublicKey = RistrettoPoint;
    type PartialKey = TOfNCurveElGamalPartialKey;
    type DecryptionShare = TOfNCurveElGamalDecryptionShare;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        let master_key = Scalar::random(rng.rng());

        let coefficients: Vec<Scalar> = (0..(self.threshold - 1))
            .map(|_| Scalar::random(rng.rng()))
            .collect();

        let partial_keys: Vec<TOfNCurveElGamalPartialKey> = (1..=self.key_count)
            .map(|i| {
                let mut key = master_key;

                for j in 0..(self.threshold - 1) {
                    key += coefficients[j as usize] * Scalar::from(i.pow(j + 1));
                }

                TOfNCurveElGamalPartialKey { id: i as i32, key }
            })
            .collect();

        (&master_key * &RISTRETTO_BASEPOINT_TABLE, partial_keys)
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &Self::Plaintext,
        public_key: &Self::PublicKey,
        rng: &mut SecureRng<R>,
    ) -> Self::Ciphertext {
        let y = Scalar::random(rng.rng());

        CurveElGamalCiphertext {
            c1: &y * &RISTRETTO_BASEPOINT_TABLE,
            c2: plaintext + y * public_key,
        }
    }

    fn partially_decrypt<'pk>(
        &self,
        rich_ciphertext: &RichCiphertext<'pk, Self::Ciphertext, Self::PublicKey>,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        TOfNCurveElGamalDecryptionShare {
            id: partial_key.id,
            c1: partial_key.key * rich_ciphertext.ciphertext.c1,
            c2: rich_ciphertext.ciphertext.c2,
        }
    }

    fn combine(
        &self,
        decryption_shares: &[Self::DecryptionShare],
        _public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        let summed: RistrettoPoint = (0usize..(self.threshold as usize))
            .zip(decryption_shares)
            .map(|(i, share)| {
                let mut b = Scalar::one();

                for i_prime in 0usize..(self.threshold as usize) {
                    if i == i_prime {
                        continue;
                    }

                    if decryption_shares[i].id == decryption_shares[i_prime].id {
                        continue;
                    }

                    b *= Scalar::from(decryption_shares[i_prime].id as u64);
                    b *= (Scalar::from(decryption_shares[i_prime].id as u64)
                        - Scalar::from(decryption_shares[i].id as u64))
                    .invert();
                }

                b * share.c1
            })
            .sum::<RistrettoPoint>();

        Ok(decryption_shares[0].c2 - summed)
    }
}

#[cfg(test)]
mod tests {
    use crate::randomness::SecureRng;
    use crate::threshold_cryptosystems::curve_el_gamal::{NOfNCurveElGamal, TOfNCurveElGamal};
    use crate::{AsymmetricThresholdCryptosystem, Enrichable};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let n_of_n_curve_elgamal = NOfNCurveElGamal { key_count: 3 };
        let (pk, sks) = n_of_n_curve_elgamal.generate_keys(&mut rng);

        let plaintext = &Scalar::from(19u64) * &RISTRETTO_BASEPOINT_TABLE;

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

        let t_of_n_curve_elgamal = TOfNCurveElGamal {
            threshold: 2,
            key_count: 3,
        };
        let (pk, sks) = t_of_n_curve_elgamal.generate_keys(&mut rng);

        let plaintext = &Scalar::from(21u64) * &RISTRETTO_BASEPOINT_TABLE;

        let ciphertext = t_of_n_curve_elgamal
            .encrypt(&plaintext, &pk, &mut rng)
            .enrich(&pk);

        let share_1 = t_of_n_curve_elgamal.partially_decrypt(&ciphertext, &sks[0]);
        let share_3 = t_of_n_curve_elgamal.partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            plaintext,
            t_of_n_curve_elgamal
                .combine(&vec![share_1, share_3], &pk)
                .unwrap()
        );
    }
}
