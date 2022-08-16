use rug::Integer;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey, SigningKey, VerificationKey,
};
use scicrypt_traits::homomorphic::HomomorphicMultiplication;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use std::ops::Rem;

/// The RSA cryptosystem.
#[derive(Copy, Clone)]
pub struct Rsa {
    modulus_size: u32,
}

/// Public key for the RSA cryptosystem.
#[derive(PartialEq, Eq, Debug)]
pub struct RsaPK {
    n: Integer,
    e: Integer,
}

/// Precomputed decryption key for RSA
pub struct PrecomputedRsaSK {
    p: Integer,
    q: Integer,
    d: Integer,
    d_p: Integer,
    d_q: Integer,
    q_inv: Integer,
}

impl PrecomputedRsaSK {
    /// Creates a new precomputed secret key using p, q, and d
    pub fn new(p: Integer, q: Integer, d: Integer) -> Self {
        let d_p = Integer::from(&d).rem(Integer::from(&p - 1));
        let d_q = Integer::from(&d).rem(Integer::from(&q - 1));
        let q_inv = Integer::from(q.invert_ref(&p).unwrap());

        PrecomputedRsaSK {
            p,
            q,
            d,
            d_p,
            d_q,
            q_inv,
        }
    }

    /// Compresses the precomputed secret key to a smaller format without precomputations
    pub fn compress(self) -> CompressedRsaSK {
        CompressedRsaSK {
            p: self.p,
            q: self.q,
            d: self.d,
        }
    }
}

/// Small secret key for RSA, which is less fast than a `PrecomputedRsaSK`.
pub struct CompressedRsaSK {
    p: Integer,
    q: Integer,
    d: Integer,
}

impl CompressedRsaSK {
    /// Creates a `PrecomputedRsaSK` from this key.
    pub fn precompute(self) -> PrecomputedRsaSK {
        PrecomputedRsaSK::new(self.p, self.q, self.d)
    }
}

/// Ciphertext of the RSA cryptosystem, which is multiplicatively homomorphic.
pub struct RsaCiphertext {
    c: Integer,
}

impl Associable<RsaPK> for RsaCiphertext {}

impl AsymmetricCryptosystem for Rsa {
    type PublicKey = RsaPK;
    type SecretKey = PrecomputedRsaSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        Rsa {
            modulus_size: security_param.to_public_key_bit_length(),
        }
    }

    fn generate_keys<R: SecureRng>(&self, rng: &mut GeneralRng<R>) -> (RsaPK, PrecomputedRsaSK) {
        let (n, lambda, p, q) = gen_rsa_modulus(self.modulus_size, rng);

        let e = Integer::from(65537);
        let d = Integer::from(e.invert_ref(&lambda).unwrap());

        (RsaPK { n, e }, PrecomputedRsaSK::new(p, q, d))
    }
}

impl EncryptionKey for RsaPK {
    type Input = Integer;
    type Plaintext = Integer;
    type Ciphertext = RsaCiphertext;

    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &Integer,
        _rng: &mut GeneralRng<R>,
    ) -> RsaCiphertext {
        RsaCiphertext {
            c: Integer::from(plaintext.pow_mod_ref(&self.e, &self.n).unwrap()),
        }
    }
}

impl DecryptionKey<RsaPK> for CompressedRsaSK {
    fn decrypt_raw(&self, public_key: &RsaPK, ciphertext: &RsaCiphertext) -> Integer {
        Integer::from(ciphertext.c.secure_pow_mod_ref(&self.d, &public_key.n))
    }
}

impl DecryptionKey<RsaPK> for PrecomputedRsaSK {
    fn decrypt_raw(
        &self,
        _public_key: &RsaPK,
        ciphertext: &<RsaPK as EncryptionKey>::Ciphertext,
    ) -> <RsaPK as EncryptionKey>::Plaintext {
        let m_p = Integer::from(ciphertext.c.secure_pow_mod_ref(&self.d_p, &self.p));
        let m_q = Integer::from(ciphertext.c.secure_pow_mod_ref(&self.d_q, &self.q));
        let h = (&self.q_inv * (m_p - &m_q)).rem(&self.p);

        m_q + h * &self.q
    }
}

impl HomomorphicMultiplication for RsaPK {
    fn mul(
        &self,
        ciphertext_a: Self::Ciphertext,
        ciphertext_b: Self::Ciphertext,
    ) -> Self::Ciphertext {
        RsaCiphertext {
            c: Integer::from(&ciphertext_a.c * &ciphertext_b.c).rem(&self.n),
        }
    }

    fn pow(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext {
        RsaCiphertext {
            c: Integer::from(ciphertext.c.pow_mod_ref(&input, &self.n).unwrap()),
        }
    }
}
/// Signature of the RSA cryptosystem
pub struct RsaSignature {
    s: Integer,
}

impl VerificationKey for RsaPK {
    type Plaintext = Integer;
    type Signature = RsaSignature;

    fn verify(&self, signature: &Self::Signature, plaintext: &Self::Plaintext) -> bool {
        return &Integer::from(signature.s.pow_mod_ref(&self.e, &self.n).unwrap()) == plaintext;
    }
}

impl SigningKey<RsaPK> for RsaSK {
    fn sign<R: SecureRng>(
        &self,
        plaintext: &<RsaPK as VerificationKey>::Plaintext,
        public_key: &RsaPK,
        _rng: &mut GeneralRng<R>,
    ) -> RsaSignature {
        RsaSignature {
            s: Integer::from(plaintext.pow_mod_ref(&self.d, &public_key.n).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::rsa::Rsa;
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt_traits::cryptosystems::{
        AsymmetricCryptosystem, DecryptionKey, EncryptionKey, SigningKey, VerificationKey,
    };
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;

    #[test]
    fn test_encrypt_decrypt_generator() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(15), &mut rng);

        assert_eq!(15, sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_b = pk.encrypt(&Integer::from(7), &mut rng);
        let ciphertext_twice = ciphertext_a * ciphertext_b;

        assert_eq!(49, sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&Integer::from(9), &mut rng);
        let ciphertext_twice = ciphertext.pow(Integer::from(4));

        assert_eq!(Integer::from(6561), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_signature_verification() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);
        let plaintext = Integer::from(10);

        let signature = sk.sign(&plaintext, &pk, &mut rng);

        assert!(pk.verify(&signature, &plaintext));
    }

    #[test]
    fn test_signature_verification_incorrect() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);
        let plaintext = Integer::from(10);

        let signature = sk.sign(&plaintext, &pk, &mut rng);

        assert!(!pk.verify(&signature, &Integer::from(11)));
    }
}
