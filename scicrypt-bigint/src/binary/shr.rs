use std::ops::{Shr, ShrAssign};

use subtle::Choice;

use crate::UnsignedInteger;


impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    pub fn shift_right_1(&mut self) -> Choice {
        todo!()
    }

    // TODO: Move to separate file
    pub fn shift_left_1(&mut self) -> Choice {
        todo!()
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
