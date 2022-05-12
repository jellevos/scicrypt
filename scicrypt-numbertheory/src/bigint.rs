use std::{mem::MaybeUninit, ops::{AddAssign, Mul}, alloc::{Layout, System, GlobalAlloc}, ptr::null_mut, fmt::Display, ffi::CStr};

use gmp_mpfr_sys::gmp::{self, mpz_t};

/// A signed BigInteger with constant-time arithmetic.
pub struct BigInteger {
    inner: mpz_t
}

impl Display for BigInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let c_buf = gmp::mpz_get_str(null_mut(), 10, &self.inner);
            let c_str = CStr::from_ptr(c_buf);
            let str_slice: &str = c_str.to_str().unwrap();
            let str = str_slice.to_owned();
            f.pad_integral(true, "", str.trim_start_matches("0"))
        }
    }
}

impl BigInteger {
    fn init(size: i32) -> Self {
        Self::zero(size as u64 * 64)
    }

    /// Creates a BigInteger with value 0. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn zero(bits: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), bits);
            let mut z = z.assume_init();
            z.size = z.alloc;  // Maximize the size given allocation
            BigInteger { inner: z }
        }
    }

    /// Creates a BigInteger with `value`. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn new(value: u64, bits: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), bits);
            let mut z = z.assume_init();
            gmp::mpz_set_ui(&mut z, value);
            z.size = z.alloc;  // Maximize the size given allocation
            BigInteger { inner: z }
        }
    }

    /// Returns true if self == 0. This is faster than checking equality.
    pub fn is_zero(&self) -> bool {
        unsafe {
            gmp::mpn_zero_p(self.inner.d.as_ptr(), self.inner.size.into()) == 1
        }
    }

    /// Extracts the numbers as a u64. This u64 will wrap silently if the integer is too big to fit in a u64.
    pub fn get_u64(&self) -> u64 {
        unsafe {
            gmp::mpz_get_ui(&self.inner)
        }
    }
}

impl AddAssign for BigInteger {
    fn add_assign(&mut self, rhs: Self) {
        unsafe {
            gmp::mpn_add_n(self.inner.d.as_ptr(), self.inner.d.as_ptr(), rhs.inner.d.as_ptr(), (self.inner.size + rhs.inner.size) as i64);
        }
    }
}

impl Mul for BigInteger {
    type Output = BigInteger;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.inner.size > self.inner.size {
            return rhs * self
        }

        unsafe {
            let mut result = BigInteger::init(self.inner.size + rhs.inner.size);

            let scratch_size = gmp::mpn_sec_mul_itch(self.inner.size as i64, rhs.inner.size as i64) as usize;
            println!("scratch size: {}", scratch_size);

            if scratch_size == 0 {
                gmp::mpn_sec_mul(
                    result.inner.d.as_mut(),
                    self.inner.d.as_ptr(),
                    self.inner.size as i64,
                    rhs.inner.d.as_ptr(),
                    rhs.inner.size as i64,
                    null_mut());

                return result
            }
            
            let scratch_layout = Layout::from_size_align(scratch_size, scratch_size).unwrap();
            let scratch =  System.alloc(scratch_layout);

            gmp::mpn_sec_mul(
                result.inner.d.as_mut(),
                self.inner.d.as_ptr(),
                self.inner.size as i64,
                rhs.inner.d.as_ptr(),
                rhs.inner.size as i64,
                scratch as *mut u64);

            System.dealloc(scratch, scratch_layout);

            result
        }
    }
}


#[cfg(test)]
mod tests {
    use super::BigInteger;

    #[test]
    fn test_zero() {
        let integer = BigInteger::zero(1024);
        assert!(integer.is_zero());
    }
    
    #[test]
    fn test_small_number() {
        let integer = BigInteger::new(15, 128);
        assert_eq!(15, integer.get_u64());
    }

    #[test]
    fn test_add_assign() {
        let mut a = BigInteger::new(123, 128);
        let b = BigInteger::new(256, 128);

        a += b;

        assert_eq!(379, a.get_u64());
    }

    #[test]
    fn test_mul_equal_size() {
        let a = BigInteger::new(23, 128);
        let b = BigInteger::new(14, 128);

        let c = a * b;

        assert_eq!(23 * 14, c.get_u64());
    }

    #[test]
    fn test_mul_larger_a() {
        let a = BigInteger::new(3, 128);
        let b = BigInteger::new(102, 64);

        let c = a * b;

        assert_eq!(3 * 102, c.get_u64());
    }

    #[test]
    fn test_mul_larger_b() {
        let a = BigInteger::new(12, 64);
        let b = BigInteger::new(25, 128);

        let c = a * b;

        assert_eq!(12 * 25, c.get_u64());
    }
}
