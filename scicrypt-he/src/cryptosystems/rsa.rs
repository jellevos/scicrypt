use scicrypt_bigint::UnsignedInteger;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey, SigningKey, VerificationKey,
};
use scicrypt_traits::homomorphic::HomomorphicMultiplication;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;

/// The RSA cryptosystem.
#[derive(Copy, Clone)]
pub struct Rsa {
    modulus_size: u32,
}

/// Public key for the RSA cryptosystem.
#[derive(PartialEq, Eq, Debug)]
pub struct RsaPK {
    n: UnsignedInteger,
    e: UnsignedInteger,
}

/// Decryption key for RSA
pub struct RsaSK {
    d: UnsignedInteger,
}

/// Ciphertext of the RSA cryptosystem, which is multiplicatively homomorphic.
pub struct RsaCiphertext {
    c: UnsignedInteger,
}

impl Associable<RsaPK> for RsaCiphertext {}

impl AsymmetricCryptosystem for Rsa {
    type PublicKey = RsaPK;
    type SecretKey = RsaSK;

    fn setup(security_param: &BitsOfSecurity) -> Self {
        Rsa {
            modulus_size: security_param.to_public_key_bit_length(),
        }
    }

    fn generate_keys<R: SecureRng>(&self, rng: &mut GeneralRng<R>) -> (RsaPK, RsaSK) {
        let (n, lambda) = gen_rsa_modulus(self.modulus_size, rng);

        let e = UnsignedInteger::new(65537, 17);
        let d = e
            .clone()
            .invert_unsecure(&lambda)
            .expect("e should always be invertible mod lambda.");

        (RsaPK { n, e }, RsaSK { d })
    }
}

impl EncryptionKey for RsaPK {
    type Input = UnsignedInteger;
    type Plaintext = UnsignedInteger;
    type Ciphertext = RsaCiphertext;

    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &UnsignedInteger,
        _rng: &mut GeneralRng<R>,
    ) -> RsaCiphertext {
        RsaCiphertext {
            c: plaintext.pow_mod(&self.e, &self.n),
        }
    }
}

impl DecryptionKey<RsaPK> for RsaSK {
    fn decrypt_raw(&self, public_key: &RsaPK, ciphertext: &RsaCiphertext) -> UnsignedInteger {
        ciphertext.c.pow_mod(&self.d, &public_key.n)
    }
}

impl HomomorphicMultiplication for RsaPK {
    fn mul(
        &self,
        ciphertext_a: Self::Ciphertext,
        ciphertext_b: Self::Ciphertext,
    ) -> Self::Ciphertext {
        RsaCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c) % &self.n,
        }
    }

    fn pow(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext {
        RsaCiphertext {
            c: ciphertext.c.pow_mod(&input, &self.n),
        }
    }
}
/// Signature of the RSA cryptosystem
pub struct RsaSignature {
    s: UnsignedInteger,
}

impl VerificationKey for RsaPK {
    type Plaintext = UnsignedInteger;
    type Signature = RsaSignature;

    fn verify(&self, signature: &Self::Signature, plaintext: &Self::Plaintext) -> bool {
        signature.s.pow_mod(&self.e, &self.n) == *plaintext
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
            s: plaintext.pow_mod(&self.d, &public_key.n),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptosystems::rsa::Rsa;
    use rand_core::OsRng;
    use scicrypt_bigint::UnsignedInteger;
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

        let ciphertext = pk.encrypt(&UnsignedInteger::from(15u64), &mut rng);

        assert_eq!(UnsignedInteger::from(15u64), sk.decrypt(&ciphertext));
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_b = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_twice = ciphertext_a * ciphertext_b;

        assert_eq!(UnsignedInteger::from(49u64), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(9u64), &mut rng);
        let ciphertext_twice = ciphertext.pow(UnsignedInteger::from(4u64));

        assert_eq!(
            UnsignedInteger::from(6561u64),
            sk.decrypt(&ciphertext_twice)
        );
    }

    #[test]
    fn test_signature_verification() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);
        let plaintext = UnsignedInteger::from(10u64);

        let signature = sk.sign(&plaintext, &pk, &mut rng);

        assert!(pk.verify(&signature, &plaintext));
    }

    #[test]
    fn test_signature_verification_incorrect() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);
        let plaintext = UnsignedInteger::from(10u64);

        let signature = sk.sign(&plaintext, &pk, &mut rng);

        assert!(!pk.verify(&signature, &UnsignedInteger::from(11u64)));
    }
}
