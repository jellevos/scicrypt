use std::{mem::MaybeUninit, ops::{AddAssign, Mul}, alloc::{Layout, System, GlobalAlloc}, ptr::null_mut, fmt::Display, ffi::CStr};

use gmp_mpfr_sys::gmp::{self, mpz_t};

const ALIGN: usize = 128;
const GMP_NUMB_BITS: u64 = 64;

/// A signed BigInteger with constant-time arithmetic.
#[derive(Debug)]
pub struct BigInteger {
    inner: mpz_t,
    supposed_size: i64,
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
    fn init(size: i64) -> Self {
        Self::zero(size as u64 * GMP_NUMB_BITS)
    }

    /// Reduces the `size` of `self`'s `inner` to the minimal size to represent its current value
    fn normalize(&mut self) {
        while self.inner.size > 0 {
            unsafe {
                if *self.inner.d.as_ptr().offset((self.inner.size - 1) as isize) != 0 {
                    break;
                }

                self.inner.size -= 1;
            }
        }
    }

    /// Creates a BigInteger with value 0. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn zero(bits: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), bits);
            let z = z.assume_init();
            BigInteger { inner: z, supposed_size: (bits / GMP_NUMB_BITS) as i64 }
        }
    }

    /// Creates a BigInteger with `value`. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn new(value: u64, bits: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), bits);
            let mut z = z.assume_init();
            gmp::mpz_set_ui(&mut z, value);
            BigInteger { inner: z, supposed_size: (bits / GMP_NUMB_BITS) as i64 }
        }
    }

    /// Creates a BigInteger from a value given as a `string` in a certain `base`. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn from_string(string: String, base: i32, bits: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), bits);
            let mut z = z.assume_init();
            gmp::mpz_set_str(&mut z, string.as_ptr() as *const i8, base);
            BigInteger { inner: z, supposed_size: (bits / GMP_NUMB_BITS) as i64 }
        }
    }

    /// Returns true if self == 0. This is faster than checking equality.
    pub fn is_zero(&self) -> bool {
        self.inner.size == 0
    }

    /// Extracts the numbers as a u64. This u64 will wrap silently if the integer is too big to fit in a u64.
    pub fn get_u64(&self) -> u64 {
        unsafe {
            gmp::mpz_get_ui(&self.inner)
        }
    }

    /// Compute `self` to the power `exponent` modulo `modulus`. The computation is constant in run time with regards to `self` and `exponent`, but variable with the size of `modulus`.
    pub fn pow_mod(&self, exponent: &BigInteger, modulus: &BigInteger) -> BigInteger {
        let mut result = BigInteger::init(modulus.supposed_size);

        let enb = exponent.supposed_size as u64 * GMP_NUMB_BITS;

        unsafe {
            let scratch_size = gmp::mpn_sec_powm_itch(self.supposed_size, enb, modulus.inner.size as i64) as usize * GMP_NUMB_BITS as usize / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_powm(
                    result.inner.d.as_mut(),
                    self.inner.d.as_ptr(),
                    self.supposed_size,
                    exponent.inner.d.as_ptr(),
                    enb,
                    modulus.inner.d.as_ptr(),
                    modulus.inner.size as i64,
                    null_mut());

                result.inner.size = modulus.inner.size;
                result.normalize();
                return result
            }
            
            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch =  System.alloc(scratch_layout);

            gmp::mpn_sec_powm(
                result.inner.d.as_mut(),
                self.inner.d.as_ptr(),
                self.supposed_size,
                exponent.inner.d.as_ptr(),
                enb,
                modulus.inner.d.as_ptr(),
                modulus.inner.size as i64,
                scratch as *mut u64);

            System.dealloc(scratch, scratch_layout);

            result.inner.size = modulus.inner.size;
            result.normalize();
            result
        }
    }
}

impl Drop for BigInteger {
    fn drop(&mut self) {
        unsafe {
            gmp::mpz_clear(&mut self.inner);
        }
    }
}

impl AddAssign for BigInteger {
    fn add_assign(&mut self, rhs: Self) {
        unsafe {
            gmp::mpn_add_n(self.inner.d.as_mut(), self.inner.d.as_ptr(), rhs.inner.d.as_ptr(), self.supposed_size);
        }
    }
}

impl Mul for &BigInteger {
    type Output = BigInteger;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.inner.size > self.inner.size {
            return rhs * self
        }

        let mut result = BigInteger::init(self.supposed_size + rhs.supposed_size);
        
        unsafe {
            let scratch_size = gmp::mpn_sec_mul_itch(self.supposed_size, rhs.supposed_size) as usize * GMP_NUMB_BITS as usize / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_mul(
                    result.inner.d.as_mut(),
                    self.inner.d.as_ptr(),
                    self.supposed_size,
                    rhs.inner.d.as_ptr(),
                    rhs.supposed_size,
                    null_mut());

                result.inner.size = self.inner.size + rhs.inner.size;
                result.normalize();
                return result
            }
            
            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch =  System.alloc(scratch_layout);

            gmp::mpn_sec_mul(
                result.inner.d.as_mut(),
                self.inner.d.as_ptr(),
                self.supposed_size,
                rhs.inner.d.as_ptr(),
                rhs.supposed_size,
                scratch as *mut u64);

            System.dealloc(scratch, scratch_layout);

            result.inner.size = self.inner.size + rhs.inner.size;
            result.normalize();
            result
        }
    }
}

impl PartialEq for BigInteger {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            gmp::mpz_cmp(&self.inner, &other.inner) == 0
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

        let c = &a * &b;

        assert_eq!(23 * 14, c.get_u64());
    }

    #[test]
    fn test_mul_larger_a() {
        let a = BigInteger::new(3, 128);
        let b = BigInteger::new(102, 64);

        let c = &a * &b;

        assert_eq!(3 * 102, c.get_u64());
    }

    #[test]
    fn test_mul_larger_b() {
        let a = BigInteger::new(12, 64);
        let b = BigInteger::from_string("393530540239137101151".to_string(), 10, 128);

        let c = &a * &b;

        let expected = BigInteger::from_string("4722366482869645213812".to_string(), 10, 128);
        assert_eq!(expected, c);
    }

    #[test]
    fn test_powexp() {
        let b = BigInteger::new(1234, 128);
        let e = BigInteger::new(23456, 128);
        let m = BigInteger::new(999331, 128);

        let res = b.pow_mod(&e, &m);

        assert_eq!(465797, res.get_u64());
    }

    #[test]
    fn test_powexp_small() {
        let b = BigInteger::new(3, 128);
        let e = BigInteger::new(2, 128);
        let m = BigInteger::new(13, 128);

        let res = b.pow_mod(&e, &m);

        assert_eq!(9, res.get_u64());
    }
}
