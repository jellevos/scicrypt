use std::ops::AddAssign;

use subtle::{Choice, ConditionallySelectable};

use crate::UnsignedInteger;

use super::ModularInteger;



impl<const LIMB_COUNT: usize> AddAssign<&Self> for ModularInteger<LIMB_COUNT> {
    fn add_assign(&mut self, rhs: &Self) {
        // TODO: Can we easily verify that these have the same MontgomeryParams? (e.g. using a debug_assert)
        let carry = self.value.add_and_carry(&rhs.value);

        let must_reduce = Choice::from((self.value >= self.modulus_params.modulus) as u8) | carry;
        self.value -= &UnsignedInteger::conditional_select(&UnsignedInteger::zero(), &self.modulus_params.modulus, must_reduce);
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{modular::MontgomeryParams, UnsignedInteger};

//     #[test]
//     fn add_overflow() {
//         let modulus = UnsignedInteger::<2>::from_str_leaky("1145325323525325234343243", 10);
//         let modulus_params = MontgomeryParams::new(modulus);

//         let mut x = 
//     }
// }
