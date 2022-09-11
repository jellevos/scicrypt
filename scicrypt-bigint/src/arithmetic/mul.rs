use std::{iter::Product, ops::Mul};

use gmp_mpfr_sys::gmp;

use crate::{scratch::Scratch, UnsignedInteger, GMP_NUMB_BITS};

impl Mul for &UnsignedInteger {
    type Output = UnsignedInteger;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.value.size > self.value.size {
            return rhs * self;
        }

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

        let mut result = UnsignedInteger::init(self.value.size + rhs.value.size);

        unsafe {
            let scratch_size = gmp::mpn_sec_mul_itch(self.value.size as i64, rhs.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            gmp::mpn_sec_mul(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
                scratch.as_mut(),
            );

            result.size_in_bits = self.size_in_bits + rhs.size_in_bits;
            result.value.size = result.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32;
            result
        }
    }
}

impl UnsignedInteger {
    /// Computes $x^2$, where $x$ is `self`. This is typically faster than performing a multiplication.
    pub fn square(&self) -> UnsignedInteger {
        debug_assert_ne!(self.value.size, 0);

        debug_assert_eq!(
            self.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
            self.value.size,
            "the operands' size in bits must match their actual size"
        );

        let mut result = UnsignedInteger::init(self.value.size * 2);

        unsafe {
            let scratch_size =
                gmp::mpn_sec_sqr_itch(self.value.size as i64) as usize * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            gmp::mpn_sec_sqr(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                scratch.as_mut(),
            );

            result.size_in_bits = self.size_in_bits * 2;
            result.value.size = result.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32; // TODO: Check if this does not cause a memory leak
            result
        }
    }
}

impl<'a> Product<&'a UnsignedInteger> for UnsignedInteger {
    fn product<I: Iterator<Item = &'a UnsignedInteger>>(mut iter: I) -> Self {
        let initial = iter.next().unwrap().clone();
        iter.fold(initial, |x, y| &x * y)
    }
}

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    #[test]
    fn test_square() {
        let x = UnsignedInteger::new(23, 64);

        let res = x.square();

        assert_eq!(UnsignedInteger::from(23u64 * 23), res);
    }

    #[test]
    fn test_mul_equal_size() {
        let a = UnsignedInteger::new(23, 64);
        let b = UnsignedInteger::new(14, 64);

        let c = &a * &b;

        assert_eq!(UnsignedInteger::from(23u64 * 14), c);
    }

    #[test]
    fn test_mul_larger_a() {
        let a = UnsignedInteger::from_string("125789402190859323905892".to_string(), 10, 128);
        let b = UnsignedInteger::new(102, 7);

        let c = &a * &b;

        assert_eq!(
            UnsignedInteger::from_string("12830519023467651038400984".to_string(), 10, 128),
            c
        );
    }

    #[test]
    fn test_mul_larger_b() {
        let a = UnsignedInteger::new(12, 64);
        let b = UnsignedInteger::from_string("393530540239137101151".to_string(), 10, 128);

        let c = &a * &b;

        let expected = UnsignedInteger::from_string("4722366482869645213812".to_string(), 10, 128);
        assert_eq!(expected, c);
    }
}
