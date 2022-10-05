use std::ops::{Shr, ShrAssign};

use subtle::Choice;

use crate::UnsignedInteger;


impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    pub fn shift_right_1(&mut self) -> Choice {
        let shifted_bits = self.limbs.map(|x| x >> 1);
        let carry_bits = self.limbs.map(|x| x << 63);
        
        for i in 0..(LIMB_COUNT - 1) {
            self.limbs[i] = shifted_bits[i] | carry_bits[i + 1]
        }
        self.limbs[LIMB_COUNT - 1] = shifted_bits[LIMB_COUNT - 1];

        Choice::from((carry_bits[0] >> 63) as u8)
    }

    // TODO: Move to separate file
    pub fn shift_left_1(&mut self) -> Choice {
        let shifted_bits = self.limbs.map(|x| x << 1);
        let carry_bits = self.limbs.map(|x| x >> 63);
        
        self.limbs[0] = shifted_bits[0];
        for i in 1..LIMB_COUNT {
            self.limbs[i] = shifted_bits[i] | carry_bits[i - 1]
        }

        Choice::from(carry_bits[LIMB_COUNT - 1] as u8)
    }
}

// impl ShrAssign<u32> for UnsignedInteger {
//     fn shr_assign(&mut self, rhs: u32) {
//         assert!(1 <= rhs);
//         assert!(rhs < GMP_NUMB_BITS);

//         unsafe {
//             gmp::mpn_rshift(
//                 self.value.d.as_mut(),
//                 self.value.d.as_ptr(),
//                 self.value.size as i64,
//                 rhs,
//             );
//         }
//     }
// }

// impl Shr<u32> for &UnsignedInteger {
//     type Output = UnsignedInteger;

//     fn shr(self, rhs: u32) -> Self::Output {
//         assert!(1 <= rhs);
//         assert!(rhs < GMP_NUMB_BITS);

//         let mut result = UnsignedInteger::init(self.value.size);

//         unsafe {
//             gmp::mpn_rshift(
//                 result.value.d.as_mut(),
//                 self.value.d.as_ptr(),
//                 self.value.size as i64,
//                 rhs,
//             );
//         }

//         result.value.size = self.value.size;
//         result
//     }
// }

#[cfg(test)]
mod tests {
    use crate::UnsignedInteger;

    #[test]
    fn shift_right_1() {
        let mut x = UnsignedInteger::<3>::from(15);
        x.shift_right_1();

        let actual = UnsignedInteger::from(7);

        assert_eq!(actual, x);
    }

    #[test]
    fn shift_left_1() {
        let mut x = UnsignedInteger::<3>::from(15);
        x.shift_left_1();

        let actual = UnsignedInteger::from(30);

        assert_eq!(actual, x);
    }
}
