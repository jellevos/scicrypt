use crate::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use crate::randomness::SecureRng;
use crate::{AsymmetricThresholdCryptosystem, DecryptionError, RichCiphertext};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

struct NOfNCurveElGamal {
    key_count: u32,
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

#[cfg(test)]
mod tests {
    use crate::randomness::SecureRng;
    use crate::threshold_cryptosystems::curve_el_gamal::NOfNCurveElGamal;
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
}
