use std::ops::{Shr, ShrAssign};

use crate::UnsignedInteger;

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
