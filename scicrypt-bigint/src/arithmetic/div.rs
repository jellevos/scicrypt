use std::ops::{Div, DivAssign};

use subtle::{ConditionallySelectable, Choice};

use crate::{UnsignedInteger, arithmetic::div};

impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    pub fn div_rem_u64(&self, divisor: u64) -> (UnsignedInteger<LIMB_COUNT>, u64) {
        let mut quotient = [0; LIMB_COUNT];
        let mut remainder: u128 = 0;

        for i in (0..LIMB_COUNT).rev() {
            let dividend: u128 = (remainder << 64) | self.limbs[i] as u128;
            quotient[i] = (dividend / divisor as u128) as u64;
            remainder = dividend % divisor as u128;
        }

        (UnsignedInteger { limbs: quotient }, remainder as u64)
    }
    
    // From: https://docs.rs/crypto-bigint/0.4.8/src/crypto_bigint/uint/div.rs.html#169-178
    pub fn div_rem(&self, divisor: &UnsignedInteger<LIMB_COUNT>) -> (UnsignedInteger<LIMB_COUNT>, UnsignedInteger<LIMB_COUNT>) {
        debug_assert_ne!(divisor, &0u64);
        debug_assert!(&*self >= divisor);

        let mut bit_difference = self.bit_length() - divisor.bit_length();
        let mut remainder = self.clone();
        let mut quotient = UnsignedInteger::<LIMB_COUNT>::zero();

        let mut c = divisor.shift_left_leaky(bit_difference);
        let mut e = UnsignedInteger::<LIMB_COUNT>::from(1).shift_left_leaky(bit_difference);

        loop {
            let mut r: UnsignedInteger<LIMB_COUNT> = remainder.clone();
            r -= &c;

            let d = -(((r.limbs[LIMB_COUNT - 1] >> 63) & 1) as i64);
            let d = d as u64;
            let choice = Choice::from((d as u8) & 1);

            remainder = UnsignedInteger::conditional_select(&remainder, &r, choice);
            r = quotient;
            r += &e;

            quotient = UnsignedInteger::conditional_select(&quotient, &r, choice);

            if bit_difference == 0 {
                break;
            }
            bit_difference -= 1;

            c.shift_right_1();
            e.shift_right_1();
        }

        (quotient, remainder)
    }
}

impl<const LIMB_COUNT: usize> Div<u64> for &UnsignedInteger<LIMB_COUNT> {
    type Output = UnsignedInteger<LIMB_COUNT>;

    fn div(self, rhs: u64) -> Self::Output {
        let (quotient, _) = self.div_rem_u64(rhs);
        quotient
    }
}

impl<const LIMB_COUNT: usize> DivAssign<&Self> for UnsignedInteger<LIMB_COUNT> {
    fn div_assign(&mut self, rhs: &Self) {
        


    }
}

// impl UnsignedInteger {
//     /// Divides `self` by `rhs` and returns the quotient and remainder (in that order).
//     pub fn div_rem(mut self, rhs: &UnsignedInteger) -> (UnsignedInteger, UnsignedInteger) {
//         // TODO: Check the other preconditions
//         debug_assert_eq!(
//             self.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
//             self.value.size,
//             "the operands' size in bits must match their actual size"
//         );
//         debug_assert_eq!(
//             rhs.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
//             rhs.value.size,
//             "the operands' size in bits must match their actual size"
//         );

//         debug_assert!(self.value.size >= rhs.value.size);
//         debug_assert!(rhs.value.size >= 1);

//         unsafe {
//             let scratch_size =
//                 gmp::mpn_sec_div_qr_itch(self.value.size as i64, rhs.value.size as i64) as usize
//                     * GMP_NUMB_BITS as usize;

//             let mut scratch = Scratch::new(scratch_size);

//             let mut res = UnsignedInteger::init(self.value.size - rhs.value.size + 1);

//             let most_significant_limb = gmp::mpn_sec_div_qr(
//                 res.value.d.as_mut(),
//                 self.value.d.as_mut(),
//                 self.value.size as i64,
//                 rhs.value.d.as_ptr(),
//                 rhs.value.size as i64,
//                 scratch.as_mut(),
//             );

//             let size = self.value.size - rhs.value.size;
//             res.value.size = size + (most_significant_limb != 0) as i32;
//             res.size_in_bits = res.value.size as u32 * GMP_NUMB_BITS;
//             res.value
//                 .d
//                 .as_ptr()
//                 .offset(size as isize)
//                 .write(most_significant_limb);

//             self.value.size = rhs.value.size;
//             self.size_in_bits = rhs.size_in_bits;

//             (res, self)
//         }
//     }
// }

// impl Div<&UnsignedInteger> for UnsignedInteger {
//     type Output = UnsignedInteger;

//     fn div(self, rhs: &UnsignedInteger) -> UnsignedInteger {
//         self.div_rem(rhs).0
//     }
// }

#[cfg(test)]
mod test {
    use crate::UnsignedInteger;

    // #[test]
    // fn test_divrem_small() {
    //     let x = UnsignedInteger::from_string_leaky("5".to_string(), 10, 3);
    //     let y = UnsignedInteger::from_string_leaky("3".to_string(), 10, 2);

    //     let (q, r) = x.div_rem(&y);

    //     assert_eq!(
    //         UnsignedInteger::from_string_leaky("1".to_string(), 10, 1),
    //         q
    //     );
    //     assert_eq!(q.value.size, 1);
    //     assert_eq!(q.size_in_bits, 64);

    //     assert_eq!(
    //         UnsignedInteger::from_string_leaky("2".to_string(), 10, 1),
    //         r
    //     );
    //     assert_eq!(r.value.size, 1);
    //     assert_eq!(r.size_in_bits, 2);
    // }

    // #[test]
    // fn test_division_small() {
    //     let x = UnsignedInteger::from_string_leaky("5".to_string(), 10, 3);
    //     let y = UnsignedInteger::from_string_leaky("3".to_string(), 10, 2);

    //     let q = x / &y;

    //     assert_eq!(
    //         UnsignedInteger::from_string_leaky("1".to_string(), 10, 1),
    //         q
    //     );
    //     assert_eq!(q.value.size, 1);
    //     assert_eq!(q.size_in_bits, 64);
    // }

    // #[test]
    // fn test_division_small_zero() {
    //     let x = UnsignedInteger::from_string_leaky("4".to_string(), 10, 3);
    //     let y = UnsignedInteger::from_string_leaky("7".to_string(), 10, 3);

    //     let q = x / &y;

    //     assert_eq!(
    //         UnsignedInteger::from_string_leaky("0".to_string(), 10, 1),
    //         q
    //     );
    //     assert_eq!(q.value.size, 0);
    //     assert_eq!(q.size_in_bits, 0);
    // }

    // #[test]
    // fn test_division() {
    //     let x = UnsignedInteger::from_string_leaky(
    //         "5378239758327583290580573280735".to_string(),
    //         10,
    //         103,
    //     );
    //     let y =
    //         UnsignedInteger::from_string_leaky("49127277414859531000011129".to_string(), 10, 86);

    //     let q = x / &y;

    //     assert_eq!(
    //         UnsignedInteger::from_string_leaky("109475".to_string(), 10, 17),
    //         q
    //     );
    //     assert_eq!(q.value.size, 1);
    //     assert_eq!(q.size_in_bits, 64);
    // }
}
