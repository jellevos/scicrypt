use std::ops::{Rem, RemAssign};

use gmp_mpfr_sys::gmp;

use crate::{scratch::Scratch, UnsignedInteger, GMP_NUMB_BITS};

impl RemAssign<&UnsignedInteger> for UnsignedInteger {
    fn rem_assign(&mut self, rhs: &Self) {
        debug_assert!(rhs.value.size.is_positive());

        // Check if this value is already reduced
        if self.value.size < rhs.value.size {
            return;
        }

        //debug_assert!(self.value.size >= rhs.value.size);
        debug_assert!(rhs.value.size >= 1);
        //debug_assert!(rhs.value.d[rhs.value.size - 1] != 0);

        debug_assert_eq!(
            self.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
            self.value.size,
            "the operands' size in bits must match their actual size"
        );
        debug_assert_eq!(
            rhs.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
            rhs.value.size,
            "the operands' size in bits must match their actual size"
        );

        unsafe {
            let scratch_size =
                gmp::mpn_sec_div_r_itch(self.value.size as i64, rhs.value.size as i64) as usize
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

impl Rem<&UnsignedInteger> for UnsignedInteger {
    type Output = UnsignedInteger;

    fn rem(mut self, rhs: &UnsignedInteger) -> Self::Output {
        self %= rhs;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    #[test]
    fn test_modulo_assign() {
        let mut a = UnsignedInteger::new(23, 64);
        let m = UnsignedInteger::new(14, 64);

        a %= &m;
        assert_eq!(UnsignedInteger::from(9u64), a);
    }

    #[test]
    fn test_modulo() {
        let a = UnsignedInteger::new(23, 64);
        let m = UnsignedInteger::new(14, 64);

        assert_eq!(UnsignedInteger::from(9u64), a % &m);
    }
}
