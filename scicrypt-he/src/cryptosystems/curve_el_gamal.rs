use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey,
};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::fmt::{Debug, Formatter};
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

/// Encryption key for curve-based ElGamal
#[derive(Debug)]
pub struct CurveElGamalPK {
    pub(crate) point: RistrettoPoint,
}

/// Ciphertext for curve-based ElGamal with the associated public key
#[derive(Debug)]
pub struct AssociatedCurveElGamalCiphertext<'pk> {
    pub(crate) ciphertext: CurveElGamalCiphertext,
    pub(crate) public_key: &'pk CurveElGamalPK,
}

impl<'pk> PartialEq for AssociatedPrecomputedCurveElGamalCiphertext<'pk> {
    fn eq(&self, other: &Self) -> bool {
        self.ciphertext == other.ciphertext
    }
}

/// Decryption key for curve-based ElGamal
pub struct CurveElGamalSK {
    key: Scalar,
}

impl<'pk> Associable<'pk, CurveElGamalPK, AssociatedCurveElGamalCiphertext<'pk>, RistrettoPoint>
    for CurveElGamalCiphertext
{
    fn associate(self, public_key: &CurveElGamalPK) -> AssociatedCurveElGamalCiphertext {
        AssociatedCurveElGamalCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

impl CurveElGamalPK {
    /// Precompute values for the encryption key to speed-up future encryptions
    pub fn precompute(self) -> PrecomputedCurveElGamalPK {
        PrecomputedCurveElGamalPK {
            point: RistrettoBasepointTable::create(&self.point),
        }
    }
}

impl CurveElGamalSK {
    fn decrypt_directly(&self, ciphertext: &CurveElGamalCiphertext) -> RistrettoPoint {
        ciphertext.c2 - self.key * ciphertext.c1
    }
}

impl<'pk>
    AsymmetricCryptosystem<
        'pk,
        PrecomputedCurveElGamalPK,
        CurveElGamalSK,
        RistrettoPoint,
        AssociatedPrecomputedCurveElGamalCiphertext<'pk>,
    > for CurveElGamal
{
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
    ) -> (PrecomputedCurveElGamalPK, CurveElGamalSK) {
        let secret_key = Scalar::random(rng.rng());
        let public_key = &secret_key * &RISTRETTO_BASEPOINT_TABLE;

        (
            CurveElGamalPK { point: public_key }.precompute(),
            CurveElGamalSK { key: secret_key },
        )
    }
}

impl<'pk> EncryptionKey<'pk, RistrettoPoint, AssociatedCurveElGamalCiphertext<'pk>>
    for CurveElGamalPK
{
    fn encrypt<IntoP: Into<RistrettoPoint>, R: SecureRng>(
        &'pk self,
        plaintext: IntoP,
        rng: &mut GeneralRng<R>,
    ) -> AssociatedCurveElGamalCiphertext {
        let y = Scalar::random(rng.rng());

        CurveElGamalCiphertext {
            c1: &y * &RISTRETTO_BASEPOINT_TABLE,
            c2: plaintext.into() + y * self.point,
        }
        .associate(self)
    }
}

/// Public key with several precomputations to speed-up encryption
pub struct PrecomputedCurveElGamalPK {
    pub(crate) point: RistrettoBasepointTable,
}

impl Debug for PrecomputedCurveElGamalPK {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.point.basepoint())
    }
}

/// Associated ciphertext for a precomputed public key
#[derive(Debug)]
pub struct AssociatedPrecomputedCurveElGamalCiphertext<'pk> {
    ciphertext: CurveElGamalCiphertext,
    #[allow(dead_code)]
    public_key: &'pk PrecomputedCurveElGamalPK,
}

impl<'pk>
    Associable<
        'pk,
        PrecomputedCurveElGamalPK,
        AssociatedPrecomputedCurveElGamalCiphertext<'pk>,
        RistrettoPoint,
    > for CurveElGamalCiphertext
{
    fn associate(
        self,
        public_key: &PrecomputedCurveElGamalPK,
    ) -> AssociatedPrecomputedCurveElGamalCiphertext {
        AssociatedPrecomputedCurveElGamalCiphertext {
            ciphertext: self,
            public_key,
        }
    }
}

impl<'pk> EncryptionKey<'pk, RistrettoPoint, AssociatedPrecomputedCurveElGamalCiphertext<'pk>>
    for PrecomputedCurveElGamalPK
{
    fn encrypt<IntoP: Into<RistrettoPoint>, R: SecureRng>(
        &'pk self,
        plaintext: IntoP,
        rng: &mut GeneralRng<R>,
    ) -> AssociatedPrecomputedCurveElGamalCiphertext {
        let y = Scalar::random(rng.rng());

        CurveElGamalCiphertext {
            c1: &y * &RISTRETTO_BASEPOINT_TABLE,
            c2: plaintext.into() + &y * &self.point,
        }
        .associate(self)
    }
}

// TODO: These double definitions can be made into one generic if associated ciphertexts have a trait
impl DecryptionKey<RistrettoPoint, AssociatedCurveElGamalCiphertext<'_>> for CurveElGamalSK {
    fn decrypt(&self, associated_ciphertext: &AssociatedCurveElGamalCiphertext) -> RistrettoPoint {
        self.decrypt_directly(&associated_ciphertext.ciphertext)
    }
}

impl DecryptionKey<RistrettoPoint, AssociatedPrecomputedCurveElGamalCiphertext<'_>>
    for CurveElGamalSK
{
    fn decrypt(
        &self,
        associated_ciphertext: &AssociatedPrecomputedCurveElGamalCiphertext,
    ) -> RistrettoPoint {
        self.decrypt_directly(&associated_ciphertext.ciphertext)
    }
}

impl<'pk> Add for &AssociatedCurveElGamalCiphertext<'pk> {
    type Output = AssociatedCurveElGamalCiphertext<'pk>;

    /// Homomorphic operation between two ElGamal ciphertexts.
    fn add(self, rhs: Self) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.ciphertext.c1 + rhs.ciphertext.c1,
            c2: self.ciphertext.c2 + rhs.ciphertext.c2,
        }
        .associate(self.public_key)
    }
}

impl<'pk> Add for &AssociatedPrecomputedCurveElGamalCiphertext<'pk> {
    type Output = AssociatedPrecomputedCurveElGamalCiphertext<'pk>;

    /// Homomorphic operation between two ElGamal ciphertexts.
    fn add(self, rhs: Self) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.ciphertext.c1 + rhs.ciphertext.c1,
            c2: self.ciphertext.c2 + rhs.ciphertext.c2,
        }
        .associate(self.public_key)
    }
}

impl<'pk> Mul<&Scalar> for &AssociatedCurveElGamalCiphertext<'pk> {
    type Output = AssociatedCurveElGamalCiphertext<'pk>;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.ciphertext.c1 * rhs,
            c2: self.ciphertext.c2 * rhs,
        }
        .associate(self.public_key)
    }
}

impl<'pk> Mul<&Scalar> for &AssociatedPrecomputedCurveElGamalCiphertext<'pk> {
    type Output = AssociatedPrecomputedCurveElGamalCiphertext<'pk>;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        CurveElGamalCiphertext {
            c1: self.ciphertext.c1 * rhs,
            c2: self.ciphertext.c2 * rhs,
        }
        .associate(self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::curve_el_gamal::{
        AssociatedPrecomputedCurveElGamalCiphertext, CurveElGamal,
    };
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
    use scicrypt_traits::randomness::GeneralRng;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext: AssociatedPrecomputedCurveElGamalCiphertext =
            pk.encrypt(RISTRETTO_BASEPOINT_POINT, &mut rng);

        assert_eq!(RISTRETTO_BASEPOINT_POINT, sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_probabilistic_encryption() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, _) = el_gamal.generate_keys(&mut rng);

        let ciphertext1 = pk.encrypt(RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext2 = pk.encrypt(RISTRETTO_BASEPOINT_POINT, &mut rng);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext_twice = &ciphertext + &ciphertext;

        assert_eq!(
            &Scalar::from(2u64) * &RISTRETTO_BASEPOINT_POINT,
            sk.decrypt(&ciphertext_twice)
        );
    }

    #[test]
    fn test_homomorphic_scalar_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let el_gamal = CurveElGamal::setup(&Default::default());
        let (pk, sk) = el_gamal.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(RISTRETTO_BASEPOINT_POINT, &mut rng);
        let ciphertext_thrice = &ciphertext * &Scalar::from(3u64);

        assert_eq!(
            &Scalar::from(3u64) * &RISTRETTO_BASEPOINT_POINT,
            sk.decrypt(&ciphertext_thrice)
        );
    }
}
