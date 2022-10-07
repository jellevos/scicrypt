use std::ops::AddAssign;

use subtle::{Choice, ConditionallySelectable};

use crate::UnsignedInteger;

use super::ModularInteger;


impl<const LIMB_COUNT: usize> AddAssign<&UnsignedInteger<LIMB_COUNT>> for ModularInteger<LIMB_COUNT> {
    fn add_assign(&mut self, rhs: &UnsignedInteger<LIMB_COUNT>) {
        let carry = self.value.add_and_carry(rhs);

        let must_reduce = Choice::from((self.value >= self.modulus_params.modulus) as u8) | carry;
        self.value -= &UnsignedInteger::conditional_select(&UnsignedInteger::zero(), &self.modulus_params.modulus, must_reduce);
    }
}

impl<const LIMB_COUNT: usize> AddAssign<&Self> for ModularInteger<LIMB_COUNT> {
    fn add_assign(&mut self, rhs: &Self) {
        // TODO: Can we easily verify that these have the same MontgomeryParams? (e.g. using a debug_assert)
        self.add_assign(&rhs.value);
    }
}

#[cfg(test)]
mod tests {
    use crate::{modular::{MontgomeryParams, ModularInteger}, UnsignedInteger};

    #[test]
    fn add_overflow() {
        let modulus = UnsignedInteger::<2>::from_str_leaky("1145325323525325234343243", 10);
        let modulus_params = MontgomeryParams::new(modulus);

        let x = UnsignedInteger::<2>::from_str_leaky("687195194115195140605946", 10);
        let mut x_mod = ModularInteger::new(x, modulus_params);

        let y = UnsignedInteger::from_str_leaky("749385129410130128937298", 10);

        x_mod += &y;

        let expected = UnsignedInteger::from_str_leaky("291255000000000035200001", 10);

        assert_eq!(expected, x_mod.retrieve());
    }
}
