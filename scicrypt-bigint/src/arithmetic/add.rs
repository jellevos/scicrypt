use std::{
    cmp::{max, min},
    iter::Sum,
    ops::{Add, AddAssign},
};

use gmp_mpfr_sys::gmp;

use crate::{scratch::Scratch, BigInteger, GMP_NUMB_BITS};

impl AddAssign<&BigInteger> for BigInteger {
    fn add_assign(&mut self, rhs: &Self) {
        // TODO: Change to debug assert
        if self.value.size.is_negative() {
            //todo!("Adding to a negative number");
            // TODO: This is copied from sub.rs, can we do better?
            assert!(self.value.size.abs() <= rhs.value.size.abs());
            if rhs.value.size == 0 {
                return;
            }
    
            unsafe {
                gmp::mpn_sub_n(
                    self.value.d.as_mut(),
                    rhs.value.d.as_ptr(),
                    self.value.d.as_ptr(),
                    -self.value.size as i64,
                );
            }
            return;
        }
        if rhs.value.size.is_negative() {
            todo!("Adding by a negative number");
        }

        debug_assert!(self.size_in_bits >= rhs.size_in_bits);

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
            self.size_in_bits = max(self.size_in_bits, rhs.size_in_bits) + carry as u32;
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

impl AddAssign<u64> for BigInteger {
    fn add_assign(&mut self, rhs: u64) {
        unsafe {
            let scratch_size =
                gmp::mpn_sec_add_1_itch(self.value.size as i64) as usize * GMP_NUMB_BITS as usize;

            let mut scratch = Scratch::new(scratch_size);

            let carry = gmp::mpn_sec_add_1(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs,
                scratch.as_mut(),
            );

            self.value.size += carry as i32;
            self.size_in_bits += carry as u32;
        }
    }
}

impl Add<u64> for BigInteger {
    type Output = BigInteger;

    fn add(mut self, rhs: u64) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> Sum<&'a BigInteger> for BigInteger {
    fn sum<I: Iterator<Item = &'a BigInteger>>(mut iter: I) -> Self {
        let initial = iter.next().unwrap().clone();
        iter.fold(initial, |x, y| x + y)
    }
}

#[cfg(test)]
mod tests {
    use crate::BigInteger;

    #[test]
    fn test_addition() {
        let mut x = BigInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
        let y = BigInteger::from_string("49127277414859531000011129".to_string(), 10, 86);

        x += &y;

        assert_eq!(
            BigInteger::from_string("5378288885604998150111573291864".to_string(), 10, 103),
            x
        );
        assert_eq!(x.size_in_bits, 103);
    }

    #[test]
    fn test_addition_u64() {
        let mut x = BigInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
        let y = 14;

        x += y;

        assert_eq!(
            BigInteger::from_string("5378239758327583290580573280749".to_string(), 10, 103),
            x
        );
        assert_eq!(x.size_in_bits, 103);
    }

    // #[test]
    // fn test_addition_negative() {
    //     let mut x = BigInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
    //     let y = BigInteger::from_string("-49127277414859531000011129".to_string(), 10, 86);

    //     x += &y;

    //     assert_eq!(
    //         BigInteger::from_string("5378190631050168431049573269606".to_string(), 10, 103),
    //         x
    //     );
    //     assert_eq!(x.size_in_bits, 103);
    // }
}
