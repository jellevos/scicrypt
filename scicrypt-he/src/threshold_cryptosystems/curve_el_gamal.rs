use crate::cryptosystems::curve_el_gamal::{CurveElGamalCiphertext, CurveElGamalPK};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use scicrypt_traits::cryptosystems::DecryptionKey;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::threshold_cryptosystems::PartialDecryptionKey;
use scicrypt_traits::threshold_cryptosystems::{
    DecryptionShare, NOfNCryptosystem, TOfNCryptosystem,
};
use scicrypt_traits::DecryptionError;

/// N-out-of-N Threshold ElGamal cryptosystem over elliptic curves: Extension of ElGamal that requires n out of n parties to
/// successfully decrypt. For this scheme there exists an efficient distributed key generation protocol.
#[derive(Copy, Clone)]
pub struct NOfNCurveElGamal;

/// Decryption key of N-out-of-N curve-based ElGamal
pub struct NOfNCurveElGamalSK {
    key: Scalar,
}

/// Decryption share of N-out-of-N curve-based ElGamal
pub struct NOfNCurveElGamalShare(CurveElGamalCiphertext);

impl NOfNCryptosystem for NOfNCurveElGamal {
    type PublicKey = CurveElGamalPK;
    type SecretKey = NOfNCurveElGamalSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        match security_param {
            BitsOfSecurity::AES128 => (),
            _ => panic!(
                "Currently only the Ristretto group is supported with security level AES128."
            ),
        }

        NOfNCurveElGamal {}
    }

    fn generate_keys<R: SecureRng>(
        &self,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (CurveElGamalPK, Vec<NOfNCurveElGamalSK>) {
        let partial_keys: Vec<NOfNCurveElGamalSK> = (0..key_count_n)
            .map(|_| NOfNCurveElGamalSK {
                key: Scalar::random(rng.rng()),
            })
            .collect();

        let master_key: Scalar = partial_keys.iter().map(|k| k.key).sum();
        let public_key = &master_key * &RISTRETTO_BASEPOINT_TABLE;

        (CurveElGamalPK { point: public_key }, partial_keys)
    }
}

impl PartialDecryptionKey<CurveElGamalPK> for NOfNCurveElGamalSK {
    type DecryptionShare = NOfNCurveElGamalShare;

    fn partial_decrypt_raw(&self, public_key: &CurveElGamalPK, ciphertext: &CurveElGamalCiphertext) -> NOfNCurveElGamalShare {
        NOfNCurveElGamalShare(CurveElGamalCiphertext {
            c1: self.key * ciphertext.c1,
            c2: ciphertext.c2,
        })
    }
}

impl DecryptionShare<CurveElGamalPK> for NOfNCurveElGamalShare {
    #[allow(clippy::op_ref)]
    fn combine(
        decryption_shares: &[Self],
        _public_key: &CurveElGamalPK,
    ) -> Result<RistrettoPoint, DecryptionError> {
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

impl TOfNCryptosystem for TOfNCurveElGamal {
    type PublicKey = CurveElGamalPK;
    type SecretKey = TOfNCurveElGamalSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        match security_param {
            BitsOfSecurity::AES128 => (),
            _ => panic!(
                "Currently only the Ristretto group is supported with security level AES128."
            ),
        }

        TOfNCurveElGamal {}
    }

    fn generate_keys<R: SecureRng>(
        &self,
        threshold_t: usize,
        key_count_n: usize,
        rng: &mut GeneralRng<R>,
    ) -> (CurveElGamalPK, Vec<TOfNCurveElGamalSK>) {
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

        (
            CurveElGamalPK {
                point: &master_key * &RISTRETTO_BASEPOINT_TABLE,
            },
            partial_keys,
        )
    }
}

/// One of the partial keys, of which t must be used to decrypt successfully.
pub struct TOfNCurveElGamalSK {
    id: i32,
    key: Scalar,
}

impl PartialDecryptionKey<CurveElGamalPK> for TOfNCurveElGamalSK {
    type DecryptionShare = TOfNCurveElGamalShare;

    fn partial_decrypt_raw(
        &self,
        _public_key: &CurveElGamalPK,
        ciphertext: &CurveElGamalCiphertext,
    ) -> TOfNCurveElGamalShare {
        TOfNCurveElGamalShare {
            id: self.id,
            c1: self.key * ciphertext.c1,
            c2: ciphertext.c2,
        }
    }
}

impl DecryptionShare<CurveElGamalPK> for TOfNCurveElGamalShare {
    fn combine(
        decryption_shares: &[Self],
        _public_key: &CurveElGamalPK,
    ) -> Result<RistrettoPoint, DecryptionError> {
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
    use crate::threshold_cryptosystems::curve_el_gamal::{
        NOfNCurveElGamal, NOfNCurveElGamalShare, TOfNCurveElGamal, TOfNCurveElGamalShare,
    };
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use scicrypt_traits::cryptosystems::{DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use scicrypt_traits::threshold_cryptosystems::{
        DecryptionShare, NOfNCryptosystem, TOfNCryptosystem, PartialDecryptionKey,
    };

    #[test]
    fn test_encrypt_decrypt_3_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = NOfNCurveElGamal::setup(&BitsOfSecurity::default());
        let (pk, sks) = el_gamal.generate_keys(3, &mut rng);

        let plaintext = &Scalar::from(19u64) * &RISTRETTO_BASEPOINT_TABLE;

        let ciphertext = pk.encrypt(&plaintext, &mut rng);

        let share_1 = sks[0].partial_decrypt(&ciphertext);
        let share_2 = sks[1].partial_decrypt(&ciphertext);
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        assert_eq!(
            plaintext,
            NOfNCurveElGamalShare::combine(&[share_1, share_2, share_3], &pk).unwrap()
        );
    }

    #[test]
    fn test_encrypt_decrypt_2_of_3() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = TOfNCurveElGamal::setup(&BitsOfSecurity::default());
        let (pk, sks) = el_gamal.generate_keys(2, 3, &mut rng);

        let plaintext = &Scalar::from(21u64) * &RISTRETTO_BASEPOINT_TABLE;

        let ciphertext = pk.encrypt(&plaintext, &mut rng);

        let share_1 = sks[0].partial_decrypt(&ciphertext);
        let share_3 = sks[2].partial_decrypt(&ciphertext);

        assert_eq!(
            plaintext,
            TOfNCurveElGamalShare::combine(&[share_1, share_3], &pk).unwrap()
        );
    }
}
