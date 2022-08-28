use std::{ops::{SubAssign, Sub}, cmp::{min, max}};

use gmp_mpfr_sys::gmp;

use crate::{BigInteger, GMP_NUMB_BITS, scratch::Scratch};

impl SubAssign<&BigInteger> for BigInteger {
    fn sub_assign(&mut self, rhs: &BigInteger) {
        debug_assert!(self.size_in_bits >= rhs.size_in_bits);

        let n = min(self.value.size, rhs.value.size);

        if n == 0 {
            return;
        }

        unsafe {
            gmp::mpn_sub_n(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                rhs.value.d.as_ptr(),
                n as i64,
            );

            let largest_size = max(self.value.size, rhs.value.size) as i32;

            self.value.size = largest_size;
            self.size_in_bits = max(self.size_in_bits, rhs.size_in_bits);
        }
    }
}

impl Sub<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn sub(mut self, rhs: &BigInteger) -> Self::Output {
        self -= rhs;
        self
    }
}

impl SubAssign<u64> for BigInteger {
    fn sub_assign(&mut self, rhs: u64) {
        unsafe {
            let scratch_size = gmp::mpn_sec_sub_1_itch(self.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize;
            
            let mut scratch = Scratch::new(scratch_size);

            gmp::mpn_sec_sub_1(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs,
                scratch.as_mut()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::BigInteger;

    #[test]
    fn test_subtract() {
        let mut x = BigInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
        let y = BigInteger::from_string("49127277414859531000011129".to_string(), 10, 86);

        x -= &y;

        assert_eq!(BigInteger::from_string("5378190631050168431049573269606".to_string(), 10, 103), x);
        assert_eq!(x.size_in_bits, 103);
    }

    #[test]
    fn test_subtract_u64() {
        let mut x = BigInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
        let y = 14;

        x -= y;

        assert_eq!(BigInteger::from_string("5378239758327583290580573280721".to_string(), 10, 103), x);
        assert_eq!(x.size_in_bits, 103);
    }
}
