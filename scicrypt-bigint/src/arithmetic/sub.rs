use std::ops::{SubAssign, Sub};

use crate::BigInteger;

impl SubAssign<&BigInteger> for BigInteger {
    fn sub_assign(&mut self, rhs: &BigInteger) {
        todo!()
    }
}

impl Sub<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn sub(mut self, rhs: &BigInteger) -> Self::Output {
        self -= rhs;
        self
    }
}
