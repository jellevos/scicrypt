use std::ops::{Sub, SubAssign};

use subtle::{Choice, ConditionallySelectable};

use crate::UnsignedInteger;

impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    /// Subtracts `other` from `self` and returns the carry/borrow bit (i.e. whether there occurs an underflow).
    pub fn subtract_and_carry(&mut self, other: &Self) -> Choice {
        let mut borrow = Choice::from(0);

        for i in 0..LIMB_COUNT {
            let old_limb = self.limbs[i];
            self.limbs[i] = self.limbs[i].wrapping_sub(other.limbs[i]).wrapping_sub(borrow.unwrap_u8() as u64);
            borrow = Choice::from(u8::conditional_select(&((old_limb < self.limbs[i]) as u8), &((old_limb <= self.limbs[i]) as u8), borrow));
        }

        borrow
    }

    /// Returns the carry/borrow, or zero if choice was 0.
    pub fn subtract_and_carry_conditionally(&mut self, other: &Self, choice: Choice) -> Choice {
        let rhs = UnsignedInteger::conditional_select(&UnsignedInteger::zero(), other, choice);
        let borrow = self.subtract_and_carry(&rhs);
        borrow
    }
}

impl<const LIMB_COUNT: usize> SubAssign<&UnsignedInteger<LIMB_COUNT>> for UnsignedInteger<LIMB_COUNT> {
    fn sub_assign(&mut self, rhs: &UnsignedInteger<LIMB_COUNT>) {
        let borrow = self.subtract_and_carry(rhs);
        debug_assert_eq!(borrow.unwrap_u8(), 0);
    }
}

impl<const LIMB_COUNT: usize> Sub<&UnsignedInteger<LIMB_COUNT>> for UnsignedInteger<LIMB_COUNT> {
    type Output = UnsignedInteger<LIMB_COUNT>;

    fn sub(mut self, rhs: &UnsignedInteger<LIMB_COUNT>) -> Self::Output {
        self -= rhs;
        self
    }
}

// impl Sub<u64> for UnsignedInteger {
//     type Output = UnsignedInteger;

//     fn sub(mut self, rhs: u64) -> Self::Output {
//         self -= rhs;
//         self
//     }
// }

// impl SubAssign<u64> for UnsignedInteger {
//     fn sub_assign(&mut self, rhs: u64) {
//         debug_assert!(self.size_in_bits >= 64);

//         unsafe {
//             let scratch_size =
//                 gmp::mpn_sec_sub_1_itch(self.value.size as i64) as usize * GMP_NUMB_BITS as usize;

//             let mut scratch = Scratch::new(scratch_size);

//             gmp::mpn_sec_sub_1(
//                 self.value.d.as_mut(),
//                 self.value.d.as_ptr(),
//                 self.value.size as i64,
//                 rhs,
//                 scratch.as_mut(),
//             );
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    #[test]
    fn test_subtract() {
        let mut x = UnsignedInteger::<2>::from_str_leaky(
            "5378239758327583290580573280735",
            10,
        );
        let y =
            UnsignedInteger::from_str_leaky("49127277414859531000011129", 10);

        x -= &y;

        assert_eq!(
            UnsignedInteger::from_str_leaky(
                "5378190631050168431049573269606",
                10,
            ),
            x
        );
    }

    // #[test]
    // fn test_subtract_u64() {
    //     let mut x = UnsignedInteger::from_str_leaky(
    //         "5378239758327583290580573280735",
    //         10,
    //     );
    //     let y = 14;

    //     x -= y;

    //     assert_eq!(
    //         UnsignedInteger::from_str_leaky(
    //             "5378239758327583290580573280721",
    //             10,
    //         ),
    //         x
    //     );
    // }
}
