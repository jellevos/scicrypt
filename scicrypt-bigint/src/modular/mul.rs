use std::ops::MulAssign;

use crate::UnsignedInteger;

use super::{ModularInteger, montgomery_reduction};


impl<const LIMB_COUNT: usize> MulAssign<&UnsignedInteger<LIMB_COUNT>> for ModularInteger<LIMB_COUNT> {
    fn mul_assign(&mut self, rhs: &UnsignedInteger<LIMB_COUNT>) {
        let product = self.value.multiply(rhs);
        self.value = montgomery_reduction(product, &self.modulus_params);
    }
}


impl<const LIMB_COUNT: usize> MulAssign for ModularInteger<LIMB_COUNT> {
    fn mul_assign(&mut self, rhs: Self) {
        self.mul_assign(&rhs.value);
    }
}
