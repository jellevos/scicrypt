use std::ops::{Rem, RemAssign};

use crate::UnsignedInteger;

// TODO: We can do better here than `div_rem`
pub fn reduce<const LIMB_COUNT: usize>(mut value: (UnsignedInteger<LIMB_COUNT>, UnsignedInteger<LIMB_COUNT>), modulus: &UnsignedInteger<LIMB_COUNT>) -> UnsignedInteger<LIMB_COUNT> {
    let (lower, upper) = value;
    
    let mut bit_difference = LIMB_COUNT * 64 + upper.bit_length() - modulus.bit_length();
    let mut quotient = UnsignedInteger::<LIMB_COUNT>::zero();

    let mut c = modulus.shift_left_leaky(bit_difference);
    let mut e = UnsignedInteger::<LIMB_COUNT>::from(1).shift_left_leaky(bit_difference);

    loop {
        let mut r: UnsignedInteger<LIMB_COUNT> = remainder.clone(); // lower_r and upper_r?
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

impl<const LIMB_COUNT: usize> Rem<u64> for UnsignedInteger<LIMB_COUNT> {
    type Output = u64;

    fn rem(self, rhs: u64) -> Self::Output {
        let mut remainder: u128 = 0;

        for i in (0..LIMB_COUNT).rev() {
            let dividend: u128 = (remainder << 64) | self.limbs[i] as u128;
            remainder = dividend % rhs as u128;
        }

        remainder as u64
    }
}


// impl RemAssign<&UnsignedInteger> for UnsignedInteger {
//     fn rem_assign(&mut self, rhs: &Self) {
//         debug_assert!(rhs.value.size.is_positive());

//         // Check if this value is already reduced
//         if self.value.size < rhs.value.size {
//             return;
//         }

//         //debug_assert!(self.value.size >= rhs.value.size);
//         debug_assert!(rhs.value.size >= 1);
//         //debug_assert!(rhs.value.d[rhs.value.size - 1] != 0);

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

//         unsafe {
//             let scratch_size =
//                 gmp::mpn_sec_div_r_itch(self.value.size as i64, rhs.value.size as i64) as usize
//                     * GMP_NUMB_BITS as usize;

//             let mut scratch = Scratch::new(scratch_size);

//             gmp::mpn_sec_div_r(
//                 self.value.d.as_mut(),
//                 self.value.size as i64,
//                 rhs.value.d.as_ptr(),
//                 rhs.value.size as i64,
//                 scratch.as_mut(),
//             );

//             self.value.size = rhs.value.size;
//             self.size_in_bits = rhs.size_in_bits;
//         }
//     }
// }

// impl Rem<&UnsignedInteger> for UnsignedInteger {
//     type Output = UnsignedInteger;

//     fn rem(mut self, rhs: &UnsignedInteger) -> Self::Output {
//         self %= rhs;
//         self
//     }
// }

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    // #[test]
    // fn test_modulo_assign() {
    //     let mut a = UnsignedInteger::from(23);
    //     let m = UnsignedInteger::from(14);

    //     a %= &m;
    //     assert_eq!(UnsignedInteger::from(9u64), a);
    // }

    // #[test]
    // fn test_modulo() {
    //     let a = UnsignedInteger::from(23);
    //     let m = UnsignedInteger::from(14);

    //     assert_eq!(UnsignedInteger::from(9u64), a % &m);
    // }
}
