use crate::cryptosystems::curve_el_gamal::{AssociatedCurveElGamalCiphertext, CurveElGamalCiphertext, CurveElGamalPK};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use scicrypt_traits::cryptosystems::{SecretKey};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::{DecryptionShare, NOfNCryptosystem, TOfNCryptosystem};
use scicrypt_traits::DecryptionError;

/// N-out-of-N Threshold ElGamal cryptosystem over elliptic curves: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
#[derive(Copy, Clone)]
pub struct NOfNCurveElGamal;

pub struct NOfNCurveElGamalSK {
    key: Scalar,
}

pub struct NOfNCurveElGamalShare(CurveElGamalCiphertext);

impl NOfNCryptosystem<'_, CurveElGamalPK, NOfNCurveElGamalSK, NOfNCurveElGamalShare> for NOfNCurveElGamal {
    fn generate_keys<R: SecureRng>(
        &self,
        security_param: &BitsOfSecurity,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (CurveElGamalPK, Vec<NOfNCurveElGamalSK>) {
        match security_param {
            BitsOfSecurity::AES128 => (),
            _ => panic!(
                "Currently only the Ristretto group is supported with security level AES128."
            ),
        }

        let partial_keys: Vec<NOfNCurveElGamalSK> = (0..key_count_n)
            .map(|_| NOfNCurveElGamalSK { key: Scalar::random(rng.rng()) })
            .collect();

        let master_key: Scalar = partial_keys.iter().map(|k| k.key).sum();
        let public_key = &master_key * &RISTRETTO_BASEPOINT_TABLE;

        (CurveElGamalPK { point: public_key }, partial_keys)
    }
}

impl SecretKey<'_, CurveElGamalPK> for NOfNCurveElGamalSK {
    type Plaintext = NOfNCurveElGamalShare;
    type Ciphertext<'pk> = AssociatedCurveElGamalCiphertext<'pk>;

    fn decrypt(&self, associated_ciphertext: &AssociatedCurveElGamalCiphertext) -> Self::Plaintext {
        NOfNCurveElGamalShare {
            0: CurveElGamalCiphertext { c1: self.key * associated_ciphertext.ciphertext.c1,
                c2: associated_ciphertext.ciphertext.c2, }
        }
    }
}

impl DecryptionShare for NOfNCurveElGamalShare {
    type Plaintext = RistrettoPoint;
    type PublicKey = CurveElGamalPK;

    fn combine(decryption_shares: &[Self], public_key: &Self::PublicKey) -> Result<Self::Plaintext, DecryptionError> {
        Ok(decryption_shares[0].0.c2 - &decryption_shares.iter().map(|share| share.0.c1).sum())
    }
}

/// Threshold ElGamal cryptosystem over elliptic curves: Extension of ElGamal that requires t out of n parties to
/// successfully decrypt.
#[derive(Copy, Clone)]
pub struct TOfNCurveElGamal;

/// A partially decrypted ciphertext, of which t must be combined to decrypt successfully.
pub struct TOfNCurveElGamalShare {
    id: i32,
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

impl TOfNCryptosystem<'_, CurveElGamalPK, TOfNCurveElGamalSK, TOfNCurveElGamalShare> for TOfNCurveElGamal {
    fn generate_keys<R: SecureRng>(
        &self,
        security_param: &BitsOfSecurity,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (CurveElGamalPK, Vec<TOfNCurveElGamalSK>) {
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

        let partial_keys: Vec<TOfNCurveElGamalSK> = (1..=key_count_n)
            .map(|i| {
                let mut key = master_key;

                for j in 0..(threshold_t - 1) {
                    key += coefficients[j as usize] * Scalar::from(i.pow((j + 1) as u32) as u64);
                }

                TOfNCurveElGamalSK { id: i as i32, key }
            })
            .collect();

        (CurveElGamalPK { point: &master_key * &RISTRETTO_BASEPOINT_TABLE }, partial_keys)
    }
}

/// One of the partial keys, of which t must be used to decrypt successfully.
struct TOfNCurveElGamalSK {
    id: i32,
    key: Scalar,
}

impl SecretKey<'_, CurveElGamalPK> for TOfNCurveElGamalSK {
    type Plaintext = TOfNCurveElGamalShare;
    type Ciphertext<'pk> = AssociatedCurveElGamalCiphertext<'pk>;

    fn decrypt(&self, associated_ciphertext: &AssociatedCurveElGamalCiphertext) -> Self::Plaintext {
        TOfNCurveElGamalShare {
            id: self.id,
            c1: self.key * associated_ciphertext.ciphertext.c1,
            c2: associated_ciphertext.ciphertext.c2,
        }
    }
}

impl DecryptionShare for TOfNCurveElGamalShare {
    type Plaintext = RistrettoPoint;
    type PublicKey = CurveElGamalPK;

    fn combine(decryption_shares: &[Self], _public_key: &Self::PublicKey) -> Result<Self::Plaintext, DecryptionError> {
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
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::threshold_cryptosystems::{
        NOfNCryptosystem, TOfNCryptosystem,
    };

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = GeneralRng::new(OsRng);

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
        let mut rng = GeneralRng::new(OsRng);

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
