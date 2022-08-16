use std::ops::{ShrAssign, Shr};

use gmp_mpfr_sys::gmp;

use crate::{BigInteger, GMP_NUMB_BITS};

/// Not a constant-time function: Reveals the actual size of self.
impl ShrAssign<u32> for BigInteger {
    fn shr_assign(&mut self, rhs: u32) {
        assert!(1 <= rhs);
        assert!(rhs as u64 <= GMP_NUMB_BITS - 1);

        unsafe {
            gmp::mpn_rshift(self.value.d.as_mut(), self.value.d.as_ptr(), self.value.size as i64, rhs);
        }
    }
}

/// Not a constant-time function: Reveals the actual size of self.
impl Shr<u32> for &BigInteger {
    type Output = BigInteger;

    fn shr(self, rhs: u32) -> Self::Output {
        assert!(1 <= rhs);
        assert!(rhs as u64 <= GMP_NUMB_BITS - 1);

        let mut result = BigInteger::init(self.value.size);

        unsafe {
            gmp::mpn_rshift(result.value.d.as_mut(), self.value.d.as_ptr(), self.value.size as i64, rhs);
        }

        result.value.size = self.value.size;
        result
    }
}
