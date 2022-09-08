use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::homomorphic::HomomorphicAddition;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use serde::{Deserialize, Serialize};
use std::convert::identity;
use std::fmt::{Debug, Formatter};

/// ElGamal over the Ristretto-encoded Curve25519 elliptic curve. The curve is provided by the
/// `curve25519-dalek` crate. ElGamal is a partially homomorphic cryptosystem.
#[derive(Copy, Clone)]
pub struct CurveElGamal;

/// ElGamal ciphertext containing curve points. The addition operator on the ciphertext is
/// reflected as the curve operation on the associated plaintext.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CurveElGamalCiphertext {
    /// First part of ciphertext
    pub c1: RistrettoPoint,
    /// Second part of ciphertext
    pub c2: RistrettoPoint,
}

impl Associable<CurveElGamalPK> for CurveElGamalCiphertext {}
impl Associable<PrecomputedCurveElGamalPK> for CurveElGamalCiphertext {}

/// Encryption key for curve-based ElGamal
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct CurveElGamalPK {
    /// Public key as a RistrettoPoint
    pub point: RistrettoPoint,
}

/// Decryption key for curve-based ElGamal
pub struct CurveElGamalSK {
    key: Scalar,
}

impl CurveElGamalPK {
    /// Precompute values for the encryption key to speed-up future encryptions
    pub fn precompute(self) -> PrecomputedCurveElGamalPK {
        PrecomputedCurveElGamalPK {
            point: RistrettoBasepointTable::create(&self.point),
        }
    }
}

impl PrecomputedCurveElGamalPK {
    /// Compresses the encryption key down to a `CurveElGamalPK` which is slower but more compact. This is useful for serialization.
    pub fn compress(self) -> CurveElGamalPK {
        CurveElGamalPK {
            point: self.point.basepoint(),
        }
    }
}

impl CurveElGamalSK {
    fn decrypt_directly(&self, ciphertext: &CurveElGamalCiphertext) -> RistrettoPoint {
        ciphertext.c2 - self.key * ciphertext.c1
    }
}

impl AsymmetricCryptosystem for CurveElGamal {
    type PublicKey = PrecomputedCurveElGamalPK;
    type SecretKey = CurveElGamalSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        match security_param {
            BitsOfSecurity::AES128
            | BitsOfSecurity::ToyParameters
            | BitsOfSecurity::Custom { pk_bits: 128 } => (),
            _ => panic!(
                "Currently only the Ristretto group is supported with security level AES128."
            ),
        }

        CurveElGamal {}
    }

    fn generate_keys<R: SecureRng>(
        &self,
        rng: &mut GeneralRng<R>,
    ) -> (PrecomputedCurveElGamalPK, CurveElGamalSK) {
        let secret_key = Scalar::random(rng.rng());
        let public_key = &secret_key * &RISTRETTO_BASEPOINT_TABLE;

        (
            CurveElGamalPK { point: public_key }.precompute(),
            CurveElGamalSK { key: secret_key },
        )
    }
}

impl EncryptionKey for CurveElGamalPK {
    type Input = Scalar;
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;

    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &RistrettoPoint,
        rng: &mut GeneralRng<R>,
    ) -> CurveElGamalCiphertext {
        let y = Scalar::random(rng.rng());

        let message = self.encrypt_determinstic(plaintext);

        self.randomize(message, &y)
    }
    fn encrypt_determinstic(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: identity(RISTRETTO_BASEPOINT_POINT),
            c2: plaintext.to_owned(),
        }
    }

    fn randomize(
        &self,
        ciphertext: Self::Ciphertext,
        randomness: &Self::Input,
    ) -> Self::Ciphertext {
        return CurveElGamalCiphertext {
            c1: randomness * &RISTRETTO_BASEPOINT_TABLE,
            c2: ciphertext.c2 + randomness * self.point,
        };
    }
}

/// Public key with several precomputations to speed-up encryption
#[derive(Clone)]
pub struct PrecomputedCurveElGamalPK {
    pub(crate) point: RistrettoBasepointTable,
}

impl Debug for PrecomputedCurveElGamalPK {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.point.basepoint())
    }
}

impl PartialEq for PrecomputedCurveElGamalPK {
    fn eq(&self, other: &Self) -> bool {
        self.point.basepoint() == other.point.basepoint()
    }
}

impl EncryptionKey for PrecomputedCurveElGamalPK {
    type Input = Scalar;
    type Plaintext = RistrettoPoint;
    type Ciphertext = CurveElGamalCiphertext;

    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &RistrettoPoint,
        rng: &mut GeneralRng<R>,
    ) -> CurveElGamalCiphertext {
        let y = Scalar::random(rng.rng());
        let message = self.encrypt_determinstic(plaintext);

        self.randomize(message, &y)
    }
    fn encrypt_determinstic(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: identity(RISTRETTO_BASEPOINT_POINT),
            c2: plaintext.to_owned(),
        }
    }

    fn randomize(
        &self,
        ciphertext: Self::Ciphertext,
        randomness: &Self::Input,
    ) -> Self::Ciphertext {
        return CurveElGamalCiphertext {
            c1: randomness * &RISTRETTO_BASEPOINT_TABLE,
            c2: ciphertext.c2 + randomness * &self.point,
        };
    }
}

impl DecryptionKey<CurveElGamalPK> for CurveElGamalSK {
    fn decrypt_raw(
        &self,
        _public_key: &CurveElGamalPK,
        ciphertext: &CurveElGamalCiphertext,
    ) -> RistrettoPoint {
        self.decrypt_directly(ciphertext)
    }

    fn decrypt_identity_raw(
        &self,
        _public_key: &CurveElGamalPK,
        ciphertext: &<CurveElGamalPK as EncryptionKey>::Ciphertext,
    ) -> bool {
        ciphertext.c2 == self.key * ciphertext.c1
    }
}

impl DecryptionKey<PrecomputedCurveElGamalPK> for CurveElGamalSK {
    fn decrypt_raw(
        &self,
        _public_key: &PrecomputedCurveElGamalPK,
        ciphertext: &CurveElGamalCiphertext,
    ) -> RistrettoPoint {
        self.decrypt_directly(ciphertext)
    }

    fn decrypt_identity_raw(
        &self,
        _public_key: &PrecomputedCurveElGamalPK,
        ciphertext: &<CurveElGamalPK as EncryptionKey>::Ciphertext,
    ) -> bool {
        ciphertext.c2 == self.key * ciphertext.c1
    }
}

impl HomomorphicAddition for CurveElGamalPK {
    fn add(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext_a.c1 + ciphertext_b.c1,
            c2: ciphertext_a.c2 + ciphertext_b.c2,
        }
    }

    fn mul_constant(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext.c1 * input,
            c2: ciphertext.c2 * input,
        }
    }

    fn sub(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext_a.c1 - ciphertext_b.c1,
            c2: ciphertext_a.c2 - ciphertext_b.c2,
        }
    }

    fn add_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext.c1,
            c2: ciphertext.c2 + constant,
        }
    }

    fn sub_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext.c1,
            c2: ciphertext.c2 - constant,
        }
    }
}

impl HomomorphicAddition for PrecomputedCurveElGamalPK {
    fn add(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext_a.c1 + ciphertext_b.c1,
            c2: ciphertext_a.c2 + ciphertext_b.c2,
        }
    }

    fn mul_constant(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext.c1 * input,
            c2: ciphertext.c2 * input,
        }
    }

    fn sub(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext_a.c1 - ciphertext_b.c1,
            c2: ciphertext_a.c2 - ciphertext_b.c2,
        }
    }

    fn add_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext.c1,
            c2: ciphertext.c2 + constant,
        }
    }

    fn sub_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext {
        CurveElGamalCiphertext {
            c1: ciphertext.c1,
            c2: ciphertext.c2 - constant,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::curve_el_gamal::CurveElGamal;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::Identity;
    use rand_core::OsRng;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);

        assert_eq!(RISTRETTO_BASEPOINT_POINT, sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_encrypt_decrypt_identity() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&RistrettoPoint::identity(), &mut rng);

        assert!(sk.decrypt_identity(&ciphertext));
    }

    #[test]
    fn test_probabilistic_encryption() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, _) = el_gamal.generate_keys(&mut rng);

        let ciphertext1 = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext2 = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext_b = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext_twice = &ciphertext_a + &ciphertext_b;

        assert_eq!(
            &Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
            sk.decrypt(&ciphertext_twice)
        );
    }

    #[test]
    fn test_homomorphic_sub() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(
            &(&Scalar::from(5u64) * &RISTRETTO_BASEPOINT_POINT),
            &mut rng,
        );
        let ciphertext_b = pk.encrypt(
            &(&Scalar::from(3u64) * &RISTRETTO_BASEPOINT_POINT),
            &mut rng,
        );
        let ciphertext_res = &ciphertext_a - &ciphertext_b;

        assert_eq!(
            &Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
            sk.decrypt(&ciphertext_res)
        );
    }

    #[test]
    fn test_homomorphic_add_constant() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext_twice = &ciphertext + &RISTRETTO_BASEPOINT_POINT;

        assert_eq!(
            &Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
            sk.decrypt(&ciphertext_twice)
        );
    }

    #[test]
    fn test_homomorphic_sub_constant() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(
            &(&Scalar::from(5u64) * &RISTRETTO_BASEPOINT_POINT),
            &mut rng,
        );
        let ciphertext_res = &ciphertext - &(&Scalar::from(3u64) * &RISTRETTO_BASEPOINT_POINT);

        assert_eq!(
            &Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
            sk.decrypt(&ciphertext_res)
        );
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext_thrice = &ciphertext * &Scalar::from(3u64);

        assert_eq!(
            &Scalar::from(3u64) * &RISTRETTO_BASEPOINT_POINT,
            sk.decrypt(&ciphertext_thrice)
        );
    }
}
