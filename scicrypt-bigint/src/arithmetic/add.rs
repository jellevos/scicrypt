use std::{
    iter::Sum,
    ops::{Add, AddAssign},
};

use subtle::Choice;
use subtle::ConditionallySelectable;

use crate::UnsignedInteger;

impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    pub fn add(&mut self, other: &Self) -> Choice {
        debug_assert_eq!(self.occupied_limbs, other.occupied_limbs);
        let mut carry = Choice::from(0);

        for i in 0..self.limbs.len() {
            self.limbs[i] = self.limbs[i].wrapping_add(other.limbs[i]).wrapping_add(carry.unwrap_u8() as u64);
            carry = Choice::from(u8::conditional_select(&((self.limbs[i] < other.limbs[i]) as u8), &((self.limbs[i] <= other.limbs[i]) as u8), carry));
        }

        carry
    }
}

impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    pub fn add2(&mut self, other: &UnsignedInteger<LIMB_COUNT>) -> Choice {
        debug_assert!(self.occupied_limbs >= other.occupied_limbs);

        let mut carry = Choice::from(0);

        for i in 0..other.occupied_limbs {
            self.limbs[i] = self.limbs[i].wrapping_add(other.limbs[i]).wrapping_add(carry.unwrap_u8() as u64);
            carry = Choice::from(u8::conditional_select(&((self.limbs[i] < other.limbs[i]) as u8), &((self.limbs[i] <= other.limbs[i]) as u8), carry));
        }

        for i in other.occupied_limbs..self.occupied_limbs {
            self.limbs[i] = self.limbs[i].wrapping_add(carry.unwrap_u8() as u64);
            carry = Choice::from(u8::conditional_select(&((self.limbs[i] < other.limbs[i]) as u8), &((self.limbs[i] <= other.limbs[i]) as u8), carry));
        }

        carry
    }
}

impl<const LIMB_COUNT: usize> AddAssign<&UnsignedInteger<LIMB_COUNT>> for UnsignedInteger<LIMB_COUNT> {
    fn add_assign(&mut self, rhs: &Self) {
        let carry = self.add(&rhs);
        debug_assert_eq!(carry.unwrap_u8(), 0);
    }
}

impl<const LIMB_COUNT: usize> Add<&UnsignedInteger<LIMB_COUNT>> for UnsignedInteger<LIMB_COUNT> {
    type Output = UnsignedInteger<LIMB_COUNT>;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const LIMB_COUNT: usize> AddAssign<u64> for UnsignedInteger<LIMB_COUNT> {
    fn add_assign(&mut self, rhs: u64) {
        let carry = self.add2(&UnsignedInteger::from(rhs));
        debug_assert_eq!(carry.unwrap_u8(), 0);
    }
}

impl<const LIMB_COUNT: usize> Add<u64> for UnsignedInteger<LIMB_COUNT> {
    type Output = UnsignedInteger<LIMB_COUNT>;

    fn add(mut self, rhs: u64) -> Self::Output {
        self += rhs;
        self
    }
}

// impl<'a> Sum<&'a UnsignedInteger> for UnsignedInteger {
//     fn sum<I: Iterator<Item = &'a UnsignedInteger>>(mut iter: I) -> Self {
//         let initial = iter.next().unwrap().clone();
//         iter.fold(initial, |x, y| x + y)
//     }
// }

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    #[test]
    fn test_addition() {
        let mut x = UnsignedInteger::<2>::from_str_leaky("5378239758327583290580573280735", 10);
        let y = UnsignedInteger::<2>::from_str_leaky("49127277414859531000011129", 10);

        x += &y;

        assert_eq!(
            UnsignedInteger::<2>::from_str_leaky("5378288885604998150111573291864", 10),
            x
        );
    }

    #[test]
    fn test_addition_overflow() {
        let mut x = UnsignedInteger::<2>::from(u64::MAX);
        let y = UnsignedInteger::from_str_leaky("3", 10);

        x += &y;

        assert_eq!(
            UnsignedInteger::from_str_leaky("18446744073709551618", 10),
            x
        );
    }

    #[test]
    fn test_addition_different_sizes() {
        let mut x = UnsignedInteger::<2>::from_str_leaky(
            "5378239758327583290580573280735",
            10,
        );
        let y = UnsignedInteger::from_str_leaky("12", 10);

        x += &y;

        assert_eq!(
            UnsignedInteger::from_str_leaky(
                "5378239758327583290580573280747",
                10,
            ),
            x
        );
    }

    #[test]
    fn test_addition_u64() {
        let mut x = UnsignedInteger::<2>::from_str_leaky(
            "5378239758327583290580573280735",
            10,
        );
        let y = 14;

        x += y;

        assert_eq!(
            UnsignedInteger::from_str_leaky(
                "5378239758327583290580573280749",
                10,
            ),
            x
        );
    }
}
