use std::{iter::Product, ops::{Mul, MulAssign}};

use crate::UnsignedInteger;

impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    /// Multiplies `self` and `other`, returning the result in two halves: `(lower, upper)` representing the least-significant half of the limbs and the most-significant ones respectively.
    pub fn multiply(&self, other: &UnsignedInteger<LIMB_COUNT>) -> (UnsignedInteger<LIMB_COUNT>, UnsignedInteger<LIMB_COUNT>) {
        let mut lower = [0; LIMB_COUNT];
        let mut upper = [0; LIMB_COUNT];
        
        for i in 0..LIMB_COUNT {
            let mut carry = 0;

            for j in 0..(LIMB_COUNT - i) {
                let new_limb = (self.limbs[i] as u128 * other.limbs[j] as u128).wrapping_add(lower[i + j] as u128).wrapping_add(carry);
                carry = new_limb >> 64;
                lower[i + j] = new_limb as u64;
            }
            for j in (LIMB_COUNT - i)..LIMB_COUNT {
                let new_limb = (self.limbs[i] as u128 * other.limbs[j] as u128).wrapping_add(upper[i + j - LIMB_COUNT] as u128).wrapping_add(carry);
                carry = new_limb >> 64;
                upper[i + j - LIMB_COUNT] = new_limb as u64;
            }

            upper[i] = carry as u64;
        }

        (UnsignedInteger { limbs: lower }, UnsignedInteger {limbs: upper})
    }

    /// Multiplies `self` and `other`, returning the result and the overflow: `(result, overflow)` representing the least-significant limbs and the most-significant limb respectively.
    pub fn multiply_u64(&self, other: u64) -> (UnsignedInteger<LIMB_COUNT>, u64) {
        todo!()
    }
}

impl<const LIMB_COUNT: usize> Mul for &UnsignedInteger<LIMB_COUNT> {
    type Output = (UnsignedInteger<LIMB_COUNT>, UnsignedInteger<LIMB_COUNT>);

    fn mul(self, rhs: Self) -> Self::Output {
        self.multiply(rhs)
    }
}

impl<const LIMB_COUNT: usize> Mul<u64> for &UnsignedInteger<LIMB_COUNT> {
    type Output = (UnsignedInteger<LIMB_COUNT>, u64);

    fn mul(self, rhs: u64) -> Self::Output {
        self.multiply_u64(rhs)
    }
}

// impl<const LIMB_COUNT: usize> MulAssign<u64> for UnsignedInteger<LIMB_COUNT> {
//     fn mul_assign(&mut self, rhs: u64) {
//         *self = &*self * rhs;
//     }
// }

// impl UnsignedInteger {
//     /// Computes $x^2$, where $x$ is `self`. This is typically faster than performing a multiplication.
//     pub fn square(&self) -> UnsignedInteger {
//         debug_assert_ne!(self.value.size, 0);

//         debug_assert_eq!(
//             self.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32,
//             self.value.size,
//             "the operands' size in bits must match their actual size"
//         );

//         let mut result = UnsignedInteger::init(self.value.size * 2);

//         unsafe {
//             let scratch_size =
//                 gmp::mpn_sec_sqr_itch(self.value.size as i64) as usize * GMP_NUMB_BITS as usize;

//             let mut scratch = Scratch::new(scratch_size);

//             gmp::mpn_sec_sqr(
//                 result.value.d.as_mut(),
//                 self.value.d.as_ptr(),
//                 self.value.size as i64,
//                 scratch.as_mut(),
//             );

//             result.size_in_bits = self.size_in_bits * 2;
//             result.value.size = result.size_in_bits.div_ceil(GMP_NUMB_BITS) as i32; // TODO: Check if this does not cause a memory leak
//             result
//         }
//     }
// }

// impl<'a> Product<&'a UnsignedInteger> for UnsignedInteger {
//     fn product<I: Iterator<Item = &'a UnsignedInteger>>(mut iter: I) -> Self {
//         let initial = iter.next().unwrap().clone();
//         iter.fold(initial, |x, y| &x * y)
//     }
// }

#[cfg(test)]
mod tests {
    use crate::{UnsignedInteger, U1024, U2048};

    // #[test]
    // fn test_square() {
    //     let x = UnsignedInteger::new(23, 64);

    //     let res = x.square();

    //     assert_eq!(UnsignedInteger::from(23u64 * 23), res);
    // }

    #[test]
    fn test_mul_equal_size() {
        let a = U1024::from(23);
        let b = U1024::from(14);

        let c = &a * &b;

        assert_eq!(U2048::from(23u64 * 14), U2048::chain(c));
    }

    // #[test]
    // fn test_mul_equal_size_reduce() {
    //     let a = UnsignedInteger::new(23, 64);
    //     let b = UnsignedInteger::new(14, 64);

    //     let mut c = &a * &b;
    //     assert_eq!(UnsignedInteger::from(23u64 * 14), c);
    //     assert_eq!(2, c.value.size);
    //     assert_eq!(128, c.size_in_bits);

    //     c.reduce_leaky();
    //     assert_eq!(UnsignedInteger::from(23u64 * 14), c);
    //     assert_eq!(1, c.value.size);
    //     assert_eq!(64, c.size_in_bits);
    // }

    // #[test]
    // fn test_mul_larger_a() {
    //     let a = UnsignedInteger::from_string_leaky("125789402190859323905892".to_string(), 10, 128);
    //     let b = UnsignedInteger::new(102, 7);

    //     let c = &a * &b;

    //     assert_eq!(
    //         UnsignedInteger::from_string_leaky("12830519023467651038400984".to_string(), 10, 128),
    //         c
    //     );
    // }

    // #[test]
    // fn test_mul_larger_b() {
    //     let a = UnsignedInteger::new(12, 64);
    //     let b = UnsignedInteger::from_string_leaky("393530540239137101151".to_string(), 10, 128);

    //     let c = &a * &b;

    //     let expected =
    //         UnsignedInteger::from_string_leaky("4722366482869645213812".to_string(), 10, 128);
    //     assert_eq!(expected, c);
    // }
}
