use std::ops::{Add, Mul, Sub};

use crate::cryptosystems::{Associable, AssociatedCiphertext, EncryptionKey};

auto trait PotentialInput {}

impl<'pk, C, PK> !PotentialInput for AssociatedCiphertext<'pk, C, PK> {}

/// Trait implemented by additively homomorphic cryptosystems
pub trait HomomorphicAddition: EncryptionKey {
    /// Combines two ciphertexts so that their decrypted value reflects some addition operation
    fn add(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext;

    /// Combines two ciphertexts so that their decrypted value reflects some subtract operation
    fn sub(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext;

    /// Applies some operation on a ciphertext so that the decrypted value reflects some multiplication with `input`
    fn mul_constant(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext;

    /// Combines two ciphertexts so that their decrypted value reflects some addition operation with a constant
    fn add_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext;

    /// Combines two ciphertexts so that their decrypted value reflects some subtract operation with a constant
    fn sub_constant(
        &self,
        ciphertext: &Self::Ciphertext,
        constant: &Self::Plaintext,
    ) -> Self::Ciphertext;
}

impl<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C> + HomomorphicAddition> Add
    for &AssociatedCiphertext<'pk, C, PK>
{
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.public_key, rhs.public_key);
        self.public_key
            .add(&self.ciphertext, &rhs.ciphertext)
            .associate(self.public_key)
    }
}

impl<
        'pk,
        P: PotentialInput,
        C: Associable<PK>,
        PK: EncryptionKey<Ciphertext = C, Plaintext = P> + HomomorphicAddition,
    > Add<&P> for &AssociatedCiphertext<'pk, C, PK>
{
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn add(self, rhs: &PK::Plaintext) -> Self::Output {
        self.public_key
            .add_constant(&self.ciphertext, rhs)
            .associate(self.public_key)
    }
}

impl<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C> + HomomorphicAddition> Sub
    for &AssociatedCiphertext<'pk, C, PK>
{
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn sub(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.public_key, rhs.public_key);
        self.public_key
            .sub(&self.ciphertext, &rhs.ciphertext)
            .associate(self.public_key)
    }
}

impl<
        'pk,
        P: PotentialInput,
        C: Associable<PK>,
        PK: EncryptionKey<Ciphertext = C, Plaintext = P> + HomomorphicAddition,
    > Sub<&P> for &AssociatedCiphertext<'pk, C, PK>
{
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn sub(self, rhs: &PK::Plaintext) -> Self::Output {
        self.public_key
            .sub_constant(&self.ciphertext, rhs)
            .associate(self.public_key)
    }
}

impl<
        'pk,
        P: PotentialInput,
        C: Associable<PK>,
        PK: EncryptionKey<Input = P, Ciphertext = C> + HomomorphicAddition,
    > Mul<&P> for &AssociatedCiphertext<'pk, C, PK>
{
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn mul(self, rhs: &PK::Input) -> Self::Output {
        self.public_key
            .mul_constant(&self.ciphertext, rhs)
            .associate(self.public_key)
    }
}

/// Trait implemented by multiplicatively homomorphic cryptosystems
pub trait HomomorphicMultiplication: EncryptionKey {
    /// Combines two ciphertexts so that their decrypted value reflects some multiplication operation
    fn mul(
        &self,
        ciphertext_a: &Self::Ciphertext,
        ciphertext_b: &Self::Ciphertext,
    ) -> Self::Ciphertext;

    /// Applies some operation on a ciphertext so that the decrypted value reflects some exponentiation with `input`
    fn pow(&self, ciphertext: &Self::Ciphertext, input: &Self::Input) -> Self::Ciphertext;
}

impl<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C> + HomomorphicMultiplication> Mul
    for &AssociatedCiphertext<'pk, C, PK>
{
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.public_key, rhs.public_key);
        self.public_key
            .mul(&self.ciphertext, &rhs.ciphertext)
            .associate(self.public_key)
    }
}

impl<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C> + HomomorphicMultiplication>
    AssociatedCiphertext<'pk, C, PK>
{
    /// Applies some operation on this ciphertext so that the decrypted value reflects some exponentiation with `input`
    pub fn pow(&self, rhs: &PK::Input) -> AssociatedCiphertext<'pk, C, PK> {
        self.public_key
            .pow(&self.ciphertext, rhs)
            .associate(self.public_key)
    }
}
