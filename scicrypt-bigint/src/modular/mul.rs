use std::ops::MulAssign;

use super::{ModularInteger, montgomery_reduction};



impl<const LIMB_COUNT: usize> MulAssign for ModularInteger<LIMB_COUNT> {
    fn mul_assign(&mut self, rhs: Self) {
        let product = self.value.multiply(&rhs.value);
        self.value = montgomery_reduction(product, &self.modulus_params);
    }
}
