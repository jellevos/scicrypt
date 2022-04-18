use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, PublicKey, SecretKey};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::ops::{Add, Mul};

/// ElGamal over the Ristretto-encoded Curve25519 elliptic curve. The curve is provided by the
/// `curve25519-dalek` crate. ElGamal is a partially homomorphic cryptosystem.
#[derive(Copy, Clone)]
pub struct CurveElGamal;

/// ElGamal ciphertext containing curve points. The addition operator on the ciphertext is
/// reflected as the curve operation on the associated plaintext.
#[derive(Debug, PartialEq)]
pub struct CurveElGamalCiphertext {
    pub(crate) c1: RistrettoPoint,
    pub(crate) c2: RistrettoPoint,
}

pub struct CurveElGamalPK {
    pub(crate) point: RistrettoPoint
}

pub struct AssociatedCurveElGamalCiphertext<'pk> {
    pub(crate) ciphertext: CurveElGamalCiphertext,
    pub(crate) public_key: &'pk CurveElGamalPK,
}

pub struct CurveElGamalSK {
    key: Scalar
}

impl CurveElGamalCiphertext {  //Associable<CurveElGamalPK, AssociatedCurveElGamalCiphertext<'_>> for
    fn associate(self, public_key: &CurveElGamalPK) -> AssociatedCurveElGamalCiphertext {
        AssociatedCurveElGamalCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

impl CurveElGamalSK {
    fn decrypt_directly(
        &self,
        ciphertext: &CurveElGamalCiphertext,
    ) -> RistrettoPoint {
        ciphertext.c2 - self.key * ciphertext.c1
    }
}

impl AsymmetricCryptosystem<'_, CurveElGamalPK, CurveElGamalSK> for CurveElGamal {
    fn setup(security_param: &BitsOfSecurity) -> Self {
        match security_param {
            BitsOfSecurity::AES128 => (),
            _ => panic!(
                "Currently only the Ristretto group is supported with security level AES128."
            ),
        }

        CurveElGamal {}
    }

    fn generate_keys<R: SecureRng>(
        &self,
        rng: &mut GeneralRng<R>,
    ) -> (CurveElGamalPK, CurveElGamalSK) {
        let secret_key = Scalar::random(rng.rng());
        let public_key = &secret_key * &RISTRETTO_BASEPOINT_TABLE;

        (CurveElGamalPK { point: public_key }, CurveElGamalSK { key: secret_key })
    }
}

impl PublicKey for CurveElGamalPK {
    type Plaintext = RistrettoPoint;
    type Ciphertext<'pk> = AssociatedCurveElGamalCiphertext<'pk>;

    fn encrypt<IntoP: Into<Self::Plaintext>, R: SecureRng>(&self, plaintext: IntoP, rng: &mut GeneralRng<R>) -> AssociatedCurveElGamalCiphertext {
        let y = Scalar::random(rng.rng());

        CurveElGamalCiphertext {
            c1: &y * &RISTRETTO_BASEPOINT_TABLE,
            c2: plaintext.into() + y * self.point,
        }.associate(&self)
    }
}

impl SecretKey<'_, CurveElGamalPK> for CurveElGamalSK {
    type Plaintext = RistrettoPoint;
    type Ciphertext<'pk> = AssociatedCurveElGamalCiphertext<'pk>;

    fn decrypt(&self, associated_ciphertext: &AssociatedCurveElGamalCiphertext) -> Self::Plaintext {
        self.decrypt_directly(&associated_ciphertext.ciphertext)
    }
}

impl Add for &CurveElGamalCiphertext {
    type Output = CurveElGamalCiphertext;

    /// Homomorphic operation between two ElGamal ciphertexts.
    fn add(self, rhs: Self) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl Mul<&Scalar> for &CurveElGamalCiphertext {
    type Output = CurveElGamalCiphertext;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.c1 * rhs,
            c2: self.c2 * rhs,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::curve_el_gamal::CurveElGamal;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, PublicKey};
    use scicrypt_traits::randomness::GeneralRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&RISTRETTO_BASEPOINT_POINT, &mut rng);

        assert_eq!(
            RISTRETTO_BASEPOINT_POINT,
            CurveElGamal::decrypt(&ciphertext.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_probabilistic_encryption() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, _) = CurveElGamal::generate_keys(&Default::default(), &mut rng);

        let ciphertext1 = CurveElGamal::encrypt(&RISTRETTO_BASEPOINT_POINT, &pk, &mut rng);
        let ciphertext2 = CurveElGamal::encrypt(&RISTRETTO_BASEPOINT_POINT, &pk, &mut rng);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);

        let ciphertext = CurveElGamal::encrypt(&RISTRETTO_BASEPOINT_POINT, &pk, &mut rng);
        let ciphertext_twice = &ciphertext + &ciphertext;

        assert_eq!(
            &Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
            CurveElGamal::decrypt(&ciphertext_twice.enrich(&pk), &sk)
        );
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);

        let ciphertext = CurveElGamal::encrypt(&RISTRETTO_BASEPOINT_POINT, &pk, &mut rng);
        let ciphertext_thrice = &ciphertext * &Scalar::from(3u64);

        assert_eq!(
            &Scalar::from(3u64) * &RISTRETTO_BASEPOINT_POINT,
            CurveElGamal::decrypt(&ciphertext_thrice.enrich(&pk), &sk)
        );
    }
}
