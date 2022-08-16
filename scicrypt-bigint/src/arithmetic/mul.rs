use std::{ops::Mul, ptr::null_mut, alloc::Layout};

use gmp_mpfr_sys::gmp;

use crate::{BigInteger, GMP_NUMB_BITS, ALIGN};

impl Mul for &BigInteger {
    type Output = BigInteger;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.value.size > self.value.size {
            return rhs * self;
        }

        debug_assert_eq!(self.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, self.value.size, "the operands' size in bits must match their actual size");
        debug_assert_eq!(rhs.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, rhs.value.size, "the operands' size in bits must match their actual size");

        let mut result = BigInteger::init(self.value.size + rhs.value.size);

        unsafe {
            let scratch_size = gmp::mpn_sec_mul_itch(self.value.size as i64, rhs.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize
                / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_mul(
                    result.value.d.as_mut(),
                    self.value.d.as_ptr(),
                    self.value.size as i64,
                    rhs.value.d.as_ptr(),
                    rhs.value.size as i64,
                    null_mut(),
                );

                result.value.size = self.value.size + rhs.value.size;
                result.size_in_bits = self.size_in_bits + rhs.size_in_bits;
                return result;
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            gmp::mpn_sec_mul(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            result.value.size = self.value.size + rhs.value.size;
            result.size_in_bits = self.size_in_bits + rhs.size_in_bits;
            result
        }
    }
}

impl BigInteger {
    pub fn square(&self) -> BigInteger {
        // TODO: Switch to more efficient squaring function
        self * self
    }
}
