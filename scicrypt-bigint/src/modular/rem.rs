use std::{ptr::null_mut, alloc::Layout, ops::{RemAssign, Rem}};

use gmp_mpfr_sys::gmp;

use crate::{BigInteger, GMP_NUMB_BITS, scratch::Scratch};

impl RemAssign<&BigInteger> for BigInteger {
    fn rem_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, self.value.size, "the operands' size in bits must match their actual size");
        debug_assert_eq!(rhs.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, rhs.value.size, "the operands' size in bits must match their actual size");

        unsafe {
            let scratch_size = gmp::mpn_sec_div_r_itch(self.value.size as i64, rhs.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            gmp::mpn_sec_div_r(
                self.value.d.as_mut(),
                self.value.size as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
                scratch.as_mut(),
            );

            self.value.size = rhs.value.size;
            self.size_in_bits = rhs.size_in_bits;
        }
    }
}

impl Rem<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn rem(mut self, rhs: &BigInteger) -> Self::Output {
        self %= rhs;
        self
    }
}
