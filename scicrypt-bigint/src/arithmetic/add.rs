use std::{ops::{AddAssign, Add}, cmp::{min, max}, iter::Sum};

use gmp_mpfr_sys::gmp;

use crate::BigInteger;

impl AddAssign<&BigInteger> for BigInteger {
    fn add_assign(&mut self, rhs: &Self) {
        let n = min(self.value.size, rhs.value.size);

        if n == 0 {
            return;
        }

        unsafe {
            let carry = gmp::mpn_add_n(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                rhs.value.d.as_ptr(),
                n as i64,
            );

            let largest_size = max(self.value.size, rhs.value.size) as i32;

            self.value.size = largest_size + carry as i32;
            self.size_in_bits = max(self.size_in_bits, rhs.size_in_bits) + carry as i64;
        }
    }
}

impl Add<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

// TODO: Also implement addition with u64 using `mpn_sec_add_1`

impl<'a> Sum<&'a BigInteger> for BigInteger {
    fn sum<I: Iterator<Item = &'a BigInteger>>(iter: I) -> Self {
        todo!()
    }
}
