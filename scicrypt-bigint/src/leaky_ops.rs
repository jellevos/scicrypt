use std::cmp::Ordering;

use gmp_mpfr_sys::gmp;

use crate::UnsignedInteger;

impl UnsignedInteger {
    /// Checks if `self` equals `other`. This function is not constant-time.
    pub fn eq_leaky(&self, other: &Self) -> bool {
        unsafe { gmp::mpz_cmp(&self.value, &other.value) == 0 }
    }

    /// Compares `self` to `other`, and returns whether it is less than `other`, equal, or greater. This function is not constant-time.
    pub fn partial_cmp_leaky(&self, other: &Self) -> Option<Ordering> {
        unsafe {
            match gmp::mpz_cmp(&self.value, &other.value) {
                0 => Some(Ordering::Equal),
                1.. => Some(Ordering::Greater),
                _ => Some(Ordering::Less),
            }
        }
    }
}

#[derive(Debug)]
pub struct LeakyUnsignedInteger<'i>(&'i UnsignedInteger);

impl UnsignedInteger {
    /// Outputs a `LeakyUnsignedInteger`, which supports overloaded operators for equality and comparisons. This makes it explicit that these operations are not constant-time.
    pub fn leak(&'_ self) -> LeakyUnsignedInteger<'_> {
        LeakyUnsignedInteger(self)
    }
}

impl<'i> PartialEq for LeakyUnsignedInteger<'i> {
    fn eq(&self, other: &Self) -> bool {
        UnsignedInteger::eq_leaky(self.0, other.0)
    }
}

impl<'i> Eq for LeakyUnsignedInteger<'i> {}

impl<'i> PartialOrd for LeakyUnsignedInteger<'i> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        UnsignedInteger::partial_cmp_leaky(self.0, other.0)
    }
}
