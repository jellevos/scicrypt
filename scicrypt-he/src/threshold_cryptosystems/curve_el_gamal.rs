use crate::cryptosystems::curve_el_gamal::{CurveElGamalCiphertext, RichCurveElGamalCiphertext};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::{
    AsymmetricNOfNCryptosystem, AsymmetricTOfNCryptosystem,
};
use scicrypt_traits::DecryptionError;

/// N-out-of-N Threshold ElGamal cryptosystem over elliptic curves: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
pub struct NOfNCurveElGamal;

impl AsymmetricNOfNCryptosystem for NOfNCurveElGamal {
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;
    type RichCiphertext<'pk> = RichCurveElGamalCiphertext<'pk>;
    type PublicKey = RistrettoPoint;
    type PartialKey = Scalar;
    type DecryptionShare = (RistrettoPoint, RistrettoPoint);

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        key_count_n: usize,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        match security_param {
            BitsOfSecurity::AES128 => (),
            _ => panic!(
                "Currently only the Ristretto group is supported with security level AES128."
            ),
        }

        let partial_keys: Vec<Scalar> = (0..key_count_n)
            .map(|_| Scalar::random(rng.rng()))
            .collect();

        let master_key: Scalar = partial_keys.iter().sum();
        let public_key = &master_key * &RISTRETTO_BASEPOINT_TABLE;

        (public_key, partial_keys)
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
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

    fn partially_decrypt(
        rich_ciphertext: &RichCurveElGamalCiphertext,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        (
            partial_key * rich_ciphertext.ciphertext.c1,
            rich_ciphertext.ciphertext.c2,
        )
    }

    #[allow(clippy::op_ref)]
    fn combine(
        decryption_shares: &[Self::DecryptionShare],
        _public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        Ok(decryption_shares[0].1 - &decryption_shares.iter().map(|(a, _)| a).sum())
    }
}

/// Threshold ElGamal cryptosystem over elliptic curves: Extension of ElGamal that requires t out of n parties to
/// successfully decrypt.
pub struct TOfNCurveElGamal;

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

impl AsymmetricTOfNCryptosystem for TOfNCurveElGamal {
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;
    type RichCiphertext<'pk> = RichCurveElGamalCiphertext<'pk>;
    type PublicKey = RistrettoPoint;
    type PartialKey = TOfNCurveElGamalPartialKey;
    type DecryptionShare = TOfNCurveElGamalDecryptionShare;

    fn generate_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        security_param: &BitsOfSecurity,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut SecureRng<R>,
    ) -> (Self::PublicKey, Vec<Self::PartialKey>) {
        match security_param {
            BitsOfSecurity::AES128 => (),
            _ => panic!(
                "Currently only the Ristretto group is supported with security level AES128."
            ),
        }

        let master_key = Scalar::random(rng.rng());

        let coefficients: Vec<Scalar> = (0..(threshold_t - 1))
            .map(|_| Scalar::random(rng.rng()))
            .collect();

        let partial_keys: Vec<TOfNCurveElGamalPartialKey> = (1..=key_count_n)
            .map(|i| {
                let mut key = master_key;

                for j in 0..(threshold_t - 1) {
                    key += coefficients[j as usize] * Scalar::from(i.pow((j + 1) as u32) as u64);
                }

                TOfNCurveElGamalPartialKey { id: i as i32, key }
            })
            .collect();

        (&master_key * &RISTRETTO_BASEPOINT_TABLE, partial_keys)
    }

    fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
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

    fn partially_decrypt(
        rich_ciphertext: &RichCurveElGamalCiphertext,
        partial_key: &Self::PartialKey,
    ) -> Self::DecryptionShare {
        TOfNCurveElGamalDecryptionShare {
            id: partial_key.id,
            c1: partial_key.key * rich_ciphertext.ciphertext.c1,
            c2: rich_ciphertext.ciphertext.c2,
        }
    }

    fn combine(
        decryption_shares: &[Self::DecryptionShare],
        _public_key: &Self::PublicKey,
    ) -> Result<Self::Plaintext, DecryptionError> {
        let summed: RistrettoPoint = decryption_shares
            .iter()
            .enumerate()
            .map(|(i, share)| {
                let mut b = Scalar::one();

                for i_prime in 0..decryption_shares.len() {
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
    use crate::threshold_cryptosystems::curve_el_gamal::{NOfNCurveElGamal, TOfNCurveElGamal};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use scicrypt_traits::randomness::SecureRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::threshold_cryptosystems::{
        AsymmetricNOfNCryptosystem, AsymmetricTOfNCryptosystem,
    };
    use scicrypt_traits::Enrichable;

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sks) = NOfNCurveElGamal::generate_keys(&BitsOfSecurity::default(), 3, &mut rng);

        let plaintext = &Scalar::from(19u64) * &RISTRETTO_BASEPOINT_TABLE;

        let ciphertext = NOfNCurveElGamal::encrypt(&plaintext, &pk, &mut rng).enrich(&pk);

        let share_1 = NOfNCurveElGamal::partially_decrypt(&ciphertext, &sks[0]);
        let share_2 = NOfNCurveElGamal::partially_decrypt(&ciphertext, &sks[1]);
        let share_3 = NOfNCurveElGamal::partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            plaintext,
            NOfNCurveElGamal::combine(&vec![share_1, share_2, share_3], &pk).unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = SecureRng::new(OsRng);

        let (pk, sks) = TOfNCurveElGamal::generate_keys(&BitsOfSecurity::default(), 2, 3, &mut rng);

        let plaintext = &Scalar::from(21u64) * &RISTRETTO_BASEPOINT_TABLE;

        let ciphertext = TOfNCurveElGamal::encrypt(&plaintext, &pk, &mut rng).enrich(&pk);

        let share_1 = TOfNCurveElGamal::partially_decrypt(&ciphertext, &sks[0]);
        let share_3 = TOfNCurveElGamal::partially_decrypt(&ciphertext, &sks[2]);

        assert_eq!(
            plaintext,
            TOfNCurveElGamal::combine(&vec![share_1, share_3], &pk).unwrap()
        );
    }
}
