use std::ops::{DivAssign, Div};

use gmp_mpfr_sys::gmp;

use crate::{BigInteger, GMP_NUMB_BITS, scratch::Scratch};

impl Div<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn div(mut self, rhs: &BigInteger) -> BigInteger {
        // TODO: Check the other preconditions
        debug_assert_eq!(self.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, self.value.size, "the operands' size in bits must match their actual size");
        debug_assert_eq!(rhs.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, rhs.value.size, "the operands' size in bits must match their actual size");

        unsafe {
            let scratch_size = gmp::mpn_sec_div_qr_itch(self.value.size as i64, rhs.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            let mut res = BigInteger::init(self.value.size - rhs.value.size);

            gmp::mpn_sec_div_qr(
                res.value.d.as_mut(),
                self.value.d.as_mut(),
                self.value.size as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
                scratch.as_mut(),
            );

            res.value.size = self.value.size - rhs.value.size + 1;
            res.size_in_bits = self.size_in_bits - rhs.size_in_bits + 1;
            return res;
        }
    }
}

impl Div<i64> for BigInteger {
    type Output = BigInteger;

    fn div(mut self, rhs: i64) -> Self::Output {
        self = self / &BigInteger::from(rhs.abs() as u64);

        if rhs.is_negative() {
            self.value.size = -self.value.size;
        }

        self
    }
}

#[cfg(test)]
mod test {
    use crate::BigInteger;

    #[test]
    fn test_division() {
        let x = BigInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
        let y = BigInteger::from_string("49127277414859531000011129".to_string(), 10, 86);

        let q = x / &y;

        assert_eq!(BigInteger::from_string("109475".to_string(), 10, 17), q);
        assert_eq!(q.size_in_bits, 17);
    }
}
