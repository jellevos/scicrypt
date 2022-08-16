use std::ops::SubAssign;

use crate::BigInteger;

impl SubAssign<&BigInteger> for BigInteger {
    fn sub_assign(&mut self, rhs: &BigInteger) {
        todo!()
    }
}
