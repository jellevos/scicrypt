use scicrypt_bigint::UnsignedInteger;
use scicrypt_numbertheory::gen_rsa_modulus;
use scicrypt_traits::cryptosystems::{
    Associable, AsymmetricCryptosystem, DecryptionKey, EncryptionKey, SigningKey, VerificationKey,
};
use scicrypt_traits::homomorphic::HomomorphicMultiplication;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::security::BitsOfSecurity;
use serde::{Deserialize, Serialize};

/// The RSA cryptosystem.
#[derive(Copy, Clone)]
pub struct Rsa {
    modulus_size: u32,
}

/// Public key for the RSA cryptosystem.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct RsaPK {
    /// Public modulus
    pub n: UnsignedInteger,
    /// Public exponentation factor
    pub e: UnsignedInteger,
}

/// Decryption key for RSA
pub struct RsaSK {
    d: UnsignedInteger,
}

/// Ciphertext of the RSA cryptosystem, which is multiplicatively homomorphic.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct RsaCiphertext {
    /// Ciphertext as an Integer
    pub c: UnsignedInteger,
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
        let (n, p, q) = gen_rsa_modulus(self.modulus_size, rng);

        // TODO: Is this the right choice?
        let lambda = (p - 1).lcm_leaky(&(q - 1));

        let e = UnsignedInteger::new(65537, 17);
        let d = e
            .clone()
            .invert_leaky(&lambda)
            .expect("e should always be invertible mod lambda.");

        (RsaPK { n, e }, RsaSK { d })
    }
}

impl EncryptionKey for RsaPK {
    type Input = UnsignedInteger;
    type Plaintext = UnsignedInteger;
    type Ciphertext = RsaCiphertext;
    type Randomness = UnsignedInteger;

    fn encrypt_raw<R: SecureRng>(
        &self,
        plaintext: &UnsignedInteger,
        _rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        self.encrypt_without_randomness(plaintext)
    }

    fn encrypt_without_randomness(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        RsaCiphertext {
            c: plaintext.pow_mod(&self.e, &self.n),
        }
    }

    fn randomize<R: SecureRng>(
        &self,
        _ciphertext: Self::Ciphertext,
        _rng: &mut GeneralRng<R>,
    ) -> Self::Ciphertext {
        panic!("Not possible to randomize Rsa ciphertext")
    }

    fn randomize_with(
        &self,
        _ciphertext: Self::Ciphertext,
        _randomness: &Self::Randomness,
    ) -> Self::Ciphertext {
        panic!("Not possible to randomize Rsa ciphertext")
    }
}

impl DecryptionKey<RsaPK> for RsaSK {
    fn decrypt_raw(&self, public_key: &RsaPK, ciphertext: &RsaCiphertext) -> UnsignedInteger {
        ciphertext.c.pow_mod(&self.d, &public_key.n)
    }

    fn decrypt_identity_raw(
        &self,
        public_key: &RsaPK,
        ciphertext: &<RsaPK as EncryptionKey>::Ciphertext,
    ) -> bool {
        // TODO: This can be optimized
        self.decrypt_raw(public_key, ciphertext) == UnsignedInteger::from(1u64)
    }
}

impl HomomorphicMultiplication for RsaPK {
    fn mul(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        RsaCiphertext {
            c: (&ciphertext_a.c * &ciphertext_b.c) % &self.n,
        }
    }

    fn pow(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext {
        RsaCiphertext {
            c: ciphertext.c.pow_mod(input, &self.n),
        }
    }
}
/// Signature of the RSA cryptosystem
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct RsaSignature {
    /// Signature as an Integer
    pub s: UnsignedInteger,
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
    fn test_encrypt_decrypt_identity() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(1), &mut rng);

        assert!(sk.decrypt_identity(&ciphertext));
    }

    #[test]
    fn test_homomorphic_mul() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext_a = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_b = pk.encrypt(&UnsignedInteger::from(7u64), &mut rng);
        let ciphertext_twice = &ciphertext_a * &ciphertext_b;

        assert_eq!(UnsignedInteger::from(49u64), sk.decrypt(&ciphertext_twice));
    }

    #[test]
    fn test_homomorphic_scalar_pow() {
        let mut rng = GeneralRng::new(OsRng);

        let rsa = Rsa::setup(&BitsOfSecurity::ToyParameters);
        let (pk, sk) = rsa.generate_keys(&mut rng);

        let ciphertext = pk.encrypt(&UnsignedInteger::from(9u64), &mut rng);
        let ciphertext_twice = ciphertext.pow(&UnsignedInteger::from(4u64));

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
