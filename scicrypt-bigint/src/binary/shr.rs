use std::ops::{Shr, ShrAssign};

use gmp_mpfr_sys::gmp;

use crate::{UnsignedInteger, GMP_NUMB_BITS};

/// Not a constant-time function: Reveals the actual size of self.
impl ShrAssign<u32> for UnsignedInteger {
    fn shr_assign(&mut self, rhs: u32) {
        debug_assert!(self.value.size.is_positive());

        assert!(1 <= rhs);
        assert!(rhs <= GMP_NUMB_BITS - 1);

        unsafe {
            gmp::mpn_rshift(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs,
            );
        }
    }
}

/// Not a constant-time function: Reveals the actual size of self.
impl Shr<u32> for &UnsignedInteger {
    type Output = UnsignedInteger;

    fn shr(self, rhs: u32) -> Self::Output {
        debug_assert!(self.value.size.is_positive());

        assert!(1 <= rhs);
        assert!(rhs <= GMP_NUMB_BITS - 1);

        let mut result = UnsignedInteger::init(self.value.size);

        unsafe {
            gmp::mpn_rshift(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs,
            );
        }

        result.value.size = self.value.size;
        result
    }
}
