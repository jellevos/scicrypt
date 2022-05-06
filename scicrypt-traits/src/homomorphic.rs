use std::ops::{Add, Mul};

use crate::cryptosystems::{Associable, EncryptionKey, AssociatedCiphertext};

auto trait PotentialInput {}

impl<'pk, C, PK> !PotentialInput for AssociatedCiphertext<'pk, C, PK> {}


pub trait HomomorphicAddition: EncryptionKey {
    fn add(&self, ciphertext_a: Self::Ciphertext, ciphertext_b: Self::Ciphertext) -> Self::Ciphertext;
    fn mul(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext;
}

impl<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C> + HomomorphicAddition> Add for AssociatedCiphertext<'pk, C, PK> {
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.public_key, rhs.public_key);
        self.public_key.add(self.ciphertext, rhs.ciphertext).associate(self.public_key)
    }
}

impl<'pk, P: PotentialInput, C: Associable<PK>, PK: EncryptionKey<Input = P, Ciphertext = C> + HomomorphicAddition> Mul<P> for AssociatedCiphertext<'pk, C, PK> {
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn mul(self, rhs: PK::Input) -> Self::Output {
        self.public_key.mul(self.ciphertext, rhs).associate(self.public_key)
    }
}

pub trait HomomorphicMultiplication: EncryptionKey {
    fn mul(&self, ciphertext_a: Self::Ciphertext, ciphertext_b: Self::Ciphertext) -> Self::Ciphertext;
    fn pow(&self, ciphertext: Self::Ciphertext, input: Self::Input) -> Self::Ciphertext;
}

// TODO: This leads to problems because PK::Plaintext can be AssociatedCiphertext<'pk, C, PK>
impl<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C> + HomomorphicMultiplication> Mul for AssociatedCiphertext<'pk, C, PK> {
    type Output = AssociatedCiphertext<'pk, C, PK>;

    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.public_key, rhs.public_key);
        self.public_key.mul(self.ciphertext, rhs.ciphertext).associate(self.public_key)
    }
}

impl<'pk, C: Associable<PK>, PK: EncryptionKey<Ciphertext = C> + HomomorphicMultiplication> AssociatedCiphertext<'pk, C, PK> {
    pub fn pow(self, rhs: PK::Input) -> AssociatedCiphertext<'pk, C, PK> {
        self.public_key.pow(self.ciphertext, rhs).associate(self.public_key)
    }
}
