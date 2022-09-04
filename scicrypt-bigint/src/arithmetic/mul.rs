use std::{iter::Product, ops::Mul};

use gmp_mpfr_sys::gmp;

use crate::{scratch::Scratch, BigInteger, GMP_NUMB_BITS};

impl Mul for &BigInteger {
    type Output = BigInteger;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.value.size.abs() > self.value.size.abs() {
            return rhs * self;
        }

        debug_assert_eq!(
            self.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
            self.value.size.abs(),
            "the operands' size in bits must match their actual size"
        );
        debug_assert_eq!(
            rhs.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
            rhs.value.size.abs(),
            "the operands' size in bits must match their actual size"
        );

        let mut result = BigInteger::init(self.value.size.abs() + rhs.value.size.abs());

        unsafe {
            let scratch_size = gmp::mpn_sec_mul_itch(self.value.size as i64, rhs.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            gmp::mpn_sec_mul(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size.abs() as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size.abs() as i64,
                scratch.as_mut(),
            );

            println!(
                "{} x {} = {}",
                self.value.size,
                rhs.value.size,
                self.value.size + rhs.value.size
            );

            let sign = self.value.size.signum() * rhs.value.size.signum();
            //result.value.size = sign * (self.value.size.abs() + rhs.value.size.abs());
            result.size_in_bits = self.size_in_bits + rhs.size_in_bits;
            result.value.size = sign * (result.size_in_bits.div_ceil(GMP_NUMB_BITS)) as i32;
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

impl<'a> Product<&'a BigInteger> for BigInteger {
    fn product<I: Iterator<Item = &'a BigInteger>>(mut iter: I) -> Self {
        let initial = iter.next().unwrap().clone();
        iter.fold(initial, |x, y| &x * &y)
    }
}

#[cfg(test)]
mod tests {
    use crate::BigInteger;

    #[test]
    fn test_mul_equal_size() {
        let a = BigInteger::new(23, 64);
        let b = BigInteger::new(14, 64);

        let c = &a * &b;

        assert_eq!(BigInteger::from(23u64 * 14), c);
    }

    #[test]
    fn test_mul_larger_a() {
        let a = BigInteger::from_string("125789402190859323905892".to_string(), 10, 128);
        let b = BigInteger::new(102, 7);

        let c = &a * &b;

        assert_eq!(
            BigInteger::from_string("12830519023467651038400984".to_string(), 10, 128),
            c
        );
    }

    #[test]
    fn test_mul_larger_b() {
        let a = BigInteger::new(12, 64);
        let b = BigInteger::from_string("393530540239137101151".to_string(), 10, 128);

        let c = &a * &b;

        let expected = BigInteger::from_string("4722366482869645213812".to_string(), 10, 128);
        assert_eq!(expected, c);
    }

    #[test]
    fn test_mul_larger_b_negative() {
        let a = BigInteger::new(12, 64);
        let b = BigInteger::from_string("-393530540239137101151".to_string(), 10, 128);

        let c = &a * &b;

        let expected = BigInteger::from_string("-4722366482869645213812".to_string(), 10, 128);
        assert_eq!(expected, c);
    }

    #[test]
    fn test_mul_larger_both_negative() {
        let a = BigInteger::from_string("-12".to_string(), 10, 64);
        let b = BigInteger::from_string("-393530540239137101151".to_string(), 10, 128);

        let c = &a * &b;

        let expected = BigInteger::from_string("4722366482869645213812".to_string(), 10, 128);
        assert_eq!(expected, c);
    }
}
