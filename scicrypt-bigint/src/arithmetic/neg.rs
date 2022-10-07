use std::ops::Neg;

use subtle::{Choice, ConditionallySelectable};

use crate::UnsignedInteger;


impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    /// Negates by wrapping the integer.
    pub fn negate_conditionally(self, choice: Choice) -> UnsignedInteger<LIMB_COUNT> {
        UnsignedInteger::conditional_select(&self, &(-self.clone()), choice)
    }
}

impl<const LIMB_COUNT: usize> Neg for UnsignedInteger<LIMB_COUNT> {
    type Output = UnsignedInteger<LIMB_COUNT>;

    fn neg(self) -> Self::Output {
        let mut shifted = self.clone();
        shifted.shift_left_1();

        self - &shifted
    }
}
