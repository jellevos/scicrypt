use std::ops::Div;

use gmp_mpfr_sys::gmp;

use crate::{scratch::Scratch, UnsignedInteger, GMP_NUMB_BITS};

impl Div<&UnsignedInteger> for UnsignedInteger {
    type Output = UnsignedInteger;

    fn div(mut self, rhs: &UnsignedInteger) -> UnsignedInteger {
        // TODO: Check the other preconditions
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

        debug_assert!(self.value.size >= rhs.value.size);
        debug_assert!(rhs.value.size >= 1);

        unsafe {
            let scratch_size =
                gmp::mpn_sec_div_qr_itch(self.value.size as i64, rhs.value.size as i64) as usize
                    * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            let mut res = UnsignedInteger::init(self.value.size.abs() - rhs.value.size.abs() + 1);

            let most_significant_limb = gmp::mpn_sec_div_qr(
                res.value.d.as_mut(),
                self.value.d.as_mut(),
                self.value.size.abs() as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size.abs() as i64,
                scratch.as_mut(),
            );

            let size = self.value.size - rhs.value.size;
            res.value.size = size + (most_significant_limb != 0) as i32;
            res.size_in_bits = res.value.size as u32 * GMP_NUMB_BITS;
            res.value
                .d
                .as_ptr()
                .offset(size as isize)
                .write(most_significant_limb);
            res
        }
    }
}

#[cfg(test)]
mod test {
    use crate::UnsignedInteger;

    #[test]
    fn test_division_small() {
        let x = UnsignedInteger::from_string("5".to_string(), 10, 3);
        let y = UnsignedInteger::from_string("3".to_string(), 10, 2);

        let q = x / &y;

        assert_eq!(UnsignedInteger::from_string("1".to_string(), 10, 1), q);
        assert_eq!(q.value.size, 1);
        assert_eq!(q.size_in_bits, 64);
    }

    #[test]
    fn test_division_small_zero() {
        let x = UnsignedInteger::from_string("4".to_string(), 10, 3);
        let y = UnsignedInteger::from_string("7".to_string(), 10, 3);

        let q = x / &y;

        assert_eq!(UnsignedInteger::from_string("0".to_string(), 10, 1), q);
        assert_eq!(q.value.size, 0);
        assert_eq!(q.size_in_bits, 0);
    }

    #[test]
    fn test_division() {
        let x =
            UnsignedInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
        let y = UnsignedInteger::from_string("49127277414859531000011129".to_string(), 10, 86);

        let q = x / &y;

        assert_eq!(
            UnsignedInteger::from_string("109475".to_string(), 10, 17),
            q
        );
        assert_eq!(q.value.size, 1);
        assert_eq!(q.size_in_bits, 64);
    }
}
