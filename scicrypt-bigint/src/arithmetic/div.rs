use std::ops::DivAssign;

use crate::BigInteger;

impl DivAssign<&BigInteger> for BigInteger {
    fn div_assign(&mut self, rhs: &BigInteger) {
        todo!()
    }
}
