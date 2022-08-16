use std::ops::{DivAssign, Div};

use crate::BigInteger;

impl DivAssign<&BigInteger> for BigInteger {
    fn div_assign(&mut self, rhs: &BigInteger) {
        todo!()
    }
}

impl Div<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn div(mut self, rhs: &BigInteger) -> Self::Output {
        self /= rhs;
        self
    }
}
