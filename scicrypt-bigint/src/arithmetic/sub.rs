use std::ops::{Sub, SubAssign};

use gmp_mpfr_sys::gmp;

use crate::{scratch::Scratch, UnsignedInteger, GMP_NUMB_BITS};

impl SubAssign<&UnsignedInteger> for UnsignedInteger {
    fn sub_assign(&mut self, rhs: &UnsignedInteger) {
        if self.size_in_bits <= rhs.size_in_bits {
            // Switch the order and reverse the sign of the result
            if self.value.size == 0 {
                return;
            }

            unsafe {
                gmp::mpn_sub_n(
                    self.value.d.as_mut(),
                    rhs.value.d.as_ptr(),
                    self.value.d.as_ptr(),
                    self.value.size as i64,
                );

                self.value.size = -rhs.value.size;
                self.size_in_bits = rhs.size_in_bits;
            }
            return;
        }

        if rhs.value.size == 0 {
            return;
        }

        unsafe {
            gmp::mpn_sub_n(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
            );
        }
    }
}

impl Sub<&UnsignedInteger> for UnsignedInteger {
    type Output = UnsignedInteger;

    fn sub(mut self, rhs: &UnsignedInteger) -> Self::Output {
        self -= rhs;
        self
    }
}

impl SubAssign<u64> for UnsignedInteger {
    fn sub_assign(&mut self, rhs: u64) {
        debug_assert!(self.size_in_bits >= 64);

        unsafe {
            let scratch_size =
                gmp::mpn_sec_sub_1_itch(self.value.size as i64) as usize * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            gmp::mpn_sec_sub_1(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs,
                scratch.as_mut(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    #[test]
    fn test_subtract() {
        let mut x = UnsignedInteger::from_string_leaky(
            "5378239758327583290580573280735".to_string(),
            10,
            103,
        );
        let y =
            UnsignedInteger::from_string_leaky("49127277414859531000011129".to_string(), 10, 86);

        x -= &y;

        assert_eq!(
            UnsignedInteger::from_string_leaky(
                "5378190631050168431049573269606".to_string(),
                10,
                103
            ),
            x
        );
        assert_eq!(x.size_in_bits, 103);
    }

    #[test]
    fn test_subtract_u64() {
        let mut x = UnsignedInteger::from_string_leaky(
            "5378239758327583290580573280735".to_string(),
            10,
            103,
        );
        let y = 14;

        x -= y;

        assert_eq!(
            UnsignedInteger::from_string_leaky(
                "5378239758327583290580573280721".to_string(),
                10,
                103
            ),
            x
        );
        assert_eq!(x.size_in_bits, 103);
    }
}
