use std::{
    iter::Sum,
    ops::{Add, AddAssign},
};

use gmp_mpfr_sys::gmp;

use crate::{scratch::Scratch, UnsignedInteger, GMP_NUMB_BITS};

impl AddAssign<&UnsignedInteger> for UnsignedInteger {
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert!(self.size_in_bits >= rhs.size_in_bits);
        debug_assert!(self.value.size >= rhs.value.size);

        if rhs.value.size == 0 {
            return;
        }

        unsafe {
            // LHS has more limbs than RHS, so add all RHS limbs to the corresponding limbs on the LHS.
            let mut carry = gmp::mpn_add_n(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
            );

            let remaining_size = (self.value.size - rhs.value.size) as i64;
            if remaining_size != 0 {
                // Propagate the carry over the remaining (more significant) limbs on the LHS.
                let scratch_size =
                    gmp::mpn_sec_add_1_itch(remaining_size) as usize * GMP_NUMB_BITS as usize;
                let mut scratch = Scratch::new(scratch_size);

                carry = gmp::mpn_sec_add_1(
                    self.value.d.as_ptr().offset(rhs.value.size as isize),
                    self.value.d.as_ptr().offset(rhs.value.size as isize),
                    remaining_size,
                    carry,
                    scratch.as_mut(),
                );
            }

            // Save the carry in a new limb
            if carry == 1u64 {
                gmp::mpz_realloc2(&mut self.value, self.value.size as u64 + 1);
                *self.value.d.as_ptr().offset(self.value.size as isize) = carry;
                self.value.size += 1;
                self.size_in_bits += 1;
            }
        }
    }
}

impl Add<&UnsignedInteger> for UnsignedInteger {
    type Output = UnsignedInteger;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign<u64> for UnsignedInteger {
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

            // Save the carry in a new limb
            if carry == 1u64 {
                gmp::mpz_realloc2(&mut self.value, self.value.size as u64 + 1);
                *self.value.d.as_ptr().offset(self.value.size as isize) = carry;
                self.value.size += 1;
                self.size_in_bits += 1;
            }
        }
    }
}

impl Add<u64> for UnsignedInteger {
    type Output = UnsignedInteger;

    fn add(mut self, rhs: u64) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> Sum<&'a UnsignedInteger> for UnsignedInteger {
    fn sum<I: Iterator<Item = &'a UnsignedInteger>>(mut iter: I) -> Self {
        let initial = iter.next().unwrap().clone();
        iter.fold(initial, |x, y| x + y)
    }
}

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    #[test]
    fn test_addition() {
        let mut x = UnsignedInteger::from_string_leaky(
            "5378239758327583290580573280735".to_string(),
            10,
            103,
        );
        let y =
            UnsignedInteger::from_string_leaky("49127277414859531000011129".to_string(), 10, 86);

        x += &y;

        assert_eq!(
            UnsignedInteger::from_string_leaky(
                "5378288885604998150111573291864".to_string(),
                10,
                103
            ),
            x
        );
        assert_eq!(x.size_in_bits, 103);
    }

    #[test]
    fn test_addition_overflow() {
        let mut x = UnsignedInteger::from(u64::MAX);
        let y = UnsignedInteger::from_string_leaky("3".to_string(), 10, 2);

        x += &y;

        assert_eq!(
            UnsignedInteger::from_string_leaky("18446744073709551618".to_string(), 10, 65),
            x
        );
        assert_eq!(x.size_in_bits, 65);
    }

    #[test]
    fn test_addition_different_sizes() {
        let mut x = UnsignedInteger::from_string_leaky(
            "5378239758327583290580573280735".to_string(),
            10,
            103,
        );
        let y = UnsignedInteger::from_string_leaky("12".to_string(), 10, 4);

        x += &y;

        assert_eq!(
            UnsignedInteger::from_string_leaky(
                "5378239758327583290580573280747".to_string(),
                10,
                103
            ),
            x
        );
        assert_eq!(x.size_in_bits, 103);
    }

    #[test]
    fn test_addition_u64() {
        let mut x = UnsignedInteger::from_string_leaky(
            "5378239758327583290580573280735".to_string(),
            10,
            103,
        );
        let y = 14;

        x += y;

        assert_eq!(
            UnsignedInteger::from_string_leaky(
                "5378239758327583290580573280749".to_string(),
                10,
                103
            ),
            x
        );
        assert_eq!(x.size_in_bits, 103);
    }
}
