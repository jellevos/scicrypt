use std::{
    alloc::Layout,
    ffi::{CStr, CString},
    fmt::Display,
    mem::MaybeUninit,
    ops::{AddAssign, Mul, RemAssign, Shr, ShrAssign, Sub},
    ptr::null_mut,
};

use gmp_mpfr_sys::{gmp::{self, mpz_t, mpz_add_ui, mpz_sub_ui, mpz_lcm, mpz_set}};
use scicrypt_traits::randomness::{SecureRng, GeneralRng};

const ALIGN: usize = 128;
const GMP_NUMB_BITS: u64 = 64;

// TODO: Consider making `bits` a const generic property.

/// A signed BigInteger with constant-time arithmetic.
#[derive(Debug)]
pub struct BigInteger {
    inner: mpz_t,
    supposed_size: i64,
}

impl Display for BigInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            if self.is_zero() {
                return f.pad_integral(true, "", "0");
            }

            let c_buf = gmp::mpz_get_str(null_mut(), 10, &self.inner);
            let c_str = CStr::from_ptr(c_buf);
            let str_slice: &str = c_str.to_str().unwrap();
            let str = str_slice.to_owned();
            f.pad_integral(true, "", str.trim_start_matches('0'))
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

    /// Generates a random number with `bits` bits. `bits` should be a multiple of 8.
    pub fn random<R: SecureRng>(bits: u64, rng: &mut GeneralRng<R>) -> Self {
        unsafe {
            let mut number = BigInteger::zero(bits);
            let limbs = gmp::mpz_limbs_write(&mut number.inner, bits.div_ceil(GMP_NUMB_BITS) as i64);
    
            for i in 0isize..bits.div_ceil(GMP_NUMB_BITS) as isize {
                let mut bytes = [0; 8];
                rng.rng().fill_bytes(&mut bytes);
                limbs.offset(i).write(u64::from_be_bytes(bytes));
            }

            number.inner.size = bits.div_ceil(GMP_NUMB_BITS) as i32;
            number
        }
    }

    /// Creates a BigInteger with value 0. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn zero(bits: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), bits);
            let z = z.assume_init();
            BigInteger {
                inner: z,
                supposed_size: bits.div_ceil(GMP_NUMB_BITS) as i64,
            }
        }
    }

    /// Creates a BigInteger with `value`. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn new(value: u64, bits: u64) -> Self {
        unsafe {
            let mut integer = BigInteger::zero(bits);
            gmp::mpz_set_ui(&mut integer.inner, value);
            integer
        }
    }

    /// Creates a BigInteger from a value given as a `string` in a certain `base`. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn from_string(string: String, base: i32, bits: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), bits);
            let mut z = z.assume_init();
            let c_string = CString::new(string).unwrap();
            gmp::mpz_set_str(&mut z, c_string.as_ptr(), base);
            BigInteger {
                inner: z,
                supposed_size: (bits / GMP_NUMB_BITS) as i64,
            }
        }
    }

    /// Returns true if self == 0. This is faster than checking equality.
    pub fn is_zero(&self) -> bool {
        self.inner.size == 0
    }

    /// Extracts the numbers as a u64. This u64 will wrap silently if the integer is too big to fit in a u64.
    pub fn get_u64(&self) -> u64 {
        unsafe { gmp::mpz_get_ui(&self.inner) }
    }

    /// Compute `self` to the power `exponent` modulo `modulus`. The computation is constant in run time with regards to the `exponent`, but it leaks the actual size of `self` and `modulus`. An easy way to protect the size of `self` is by adding `modulus` to it. The modulus cannot be smaller than the other operands.
    pub fn pow_mod(&self, exponent: &BigInteger, modulus: &BigInteger) -> BigInteger {
        // The actual size of the modulus cannot be smaller than the supposed size of the other operands.
        assert!(self.supposed_size <= modulus.inner.size as i64);
        assert!(exponent.supposed_size <= modulus.inner.size as i64);

        let mut result = BigInteger::init(modulus.supposed_size);

        // TODO: Make supposed_size in bits so we can also have small bit counts e.g. RSA's value e

        let enb = exponent.supposed_size as u64 * GMP_NUMB_BITS;

        unsafe {
            let scratch_size =
                gmp::mpn_sec_powm_itch(self.inner.size as i64, enb, modulus.inner.size as i64) as usize
                    * GMP_NUMB_BITS as usize
                    / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_powm(
                    result.inner.d.as_mut(),
                    self.inner.d.as_ptr(),
                    self.supposed_size,
                    exponent.inner.d.as_ptr(),
                    enb,
                    modulus.inner.d.as_ptr(),
                    modulus.inner.size as i64,
                    null_mut(),
                );

                result.inner.size = modulus.inner.size;
                result.normalize();
                return result;
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            gmp::mpn_sec_powm(
                result.inner.d.as_mut(),
                self.inner.d.as_ptr(),
                self.inner.size as i64,
                exponent.inner.d.as_ptr(),
                enb,
                modulus.inner.d.as_ptr(),
                modulus.inner.size as i64,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            result.inner.size = modulus.inner.size;
            result.normalize();
            result
        }
    }

    pub fn set_bit(&mut self, bit_index: u64) {
        unsafe {
            gmp::mpz_setbit(&mut self.inner, bit_index);
        }
    }

    /// Computes self modulo a u64 number. This function is not constant-time.
    pub fn mod_u(&self, modulus: u64) -> u64 {
        unsafe {
            gmp::mpz_fdiv_ui(&self.inner, modulus)
        }
    }

    /// Returns true when this number is prime. This function is not constant-time. Internally it uses Baille-PSW.
    pub fn is_probably_prime(&self) -> bool {
        unsafe {
            gmp::mpz_probab_prime_p(&self.inner, 25) > 0
        }
    }

    /// Computes `self^-1 mod modulus`, taking ownership of `self`. Returns None if no inverse exists. `modulus` must be odd.
    pub fn invert(mut self, modulus: &BigInteger) -> Option<BigInteger> {
        //assert_eq!(self.supposed_size, modulus.supposed_size);
        //self.supposed_size = modulus.inner.size as i64;

        let mut result = BigInteger::init(modulus.supposed_size);

        unsafe {
            let scratch_size = gmp::mpn_sec_invert_itch(self.supposed_size)
                as usize
                * GMP_NUMB_BITS as usize
                / 8;

            if scratch_size == 0 {
                let is_valid = gmp::mpn_sec_invert(
                    result.inner.d.as_mut(),
                    self.inner.d.as_ptr(),
                    modulus.inner.d.as_ptr(),
                    modulus.supposed_size,
                    (self.supposed_size + modulus.supposed_size) as u64 * GMP_NUMB_BITS,
                    null_mut(),
                );

                // Check if an inverse exists
                if is_valid == 0 {
                    return None;
                }

                result.inner.size = modulus.inner.size;
                result.normalize();
                return Some(result);
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            let is_valid = gmp::mpn_sec_invert(
                result.inner.d.as_mut(),
                self.inner.d.as_ptr(),
                modulus.inner.d.as_ptr(),
                modulus.supposed_size,
                (self.supposed_size + modulus.supposed_size) as u64 * GMP_NUMB_BITS,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            // Check if an inverse exists
            if is_valid == 0 {
                return None;
            }

            result.inner.size = modulus.inner.size;
            result.normalize();
            return Some(result);
        }
    }

    // Computes the least common multiple between self and other. This function is not constant-time.
    pub fn lcm(&self, other: &BigInteger) -> BigInteger {
        let mut result = BigInteger::init(self.supposed_size);

        unsafe {
            mpz_lcm(&mut result.inner, &self.inner, &other.inner);
        }

        result.normalize();
        result
    }
}

impl Drop for BigInteger {
    fn drop(&mut self) {
        unsafe {
            gmp::mpz_clear(&mut self.inner);
        }
    }
}

impl AddAssign<&BigInteger> for BigInteger {
    fn add_assign(&mut self, rhs: &Self) {
        unsafe {
            gmp::mpn_add_n(
                self.inner.d.as_mut(),
                self.inner.d.as_ptr(),
                rhs.inner.d.as_ptr(),
                self.supposed_size,
            );
        }
    }
}

impl AddAssign<u64> for BigInteger {
    fn add_assign(&mut self, rhs: u64) {
        unsafe {
            mpz_add_ui(&mut self.inner, &self.inner, rhs);
        }
    }
}

impl Sub<u64> for &BigInteger {
    type Output = BigInteger;

    fn sub(self, rhs: u64) -> Self::Output {
        let mut result = BigInteger::init(self.supposed_size);

        unsafe {
            mpz_sub_ui(&mut result.inner, &result.inner, rhs);
        }

        result
    }
}

impl Mul for &BigInteger {
    type Output = BigInteger;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.inner.size > self.inner.size {
            return rhs * self;
        }

        let mut result = BigInteger::init(self.supposed_size + rhs.supposed_size);

        unsafe {
            let scratch_size = gmp::mpn_sec_mul_itch(self.supposed_size, rhs.supposed_size)
                as usize
                * GMP_NUMB_BITS as usize
                / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_mul(
                    result.inner.d.as_mut(),
                    self.inner.d.as_ptr(),
                    self.supposed_size,
                    rhs.inner.d.as_ptr(),
                    rhs.supposed_size,
                    null_mut(),
                );

                result.inner.size = self.inner.size + rhs.inner.size;
                result.normalize();
                return result;
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            gmp::mpn_sec_mul(
                result.inner.d.as_mut(),
                self.inner.d.as_ptr(),
                self.supposed_size,
                rhs.inner.d.as_ptr(),
                rhs.supposed_size,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            result.inner.size = self.inner.size + rhs.inner.size;
            result.normalize();
            result
        }
    }
}

impl RemAssign<&BigInteger> for BigInteger {
    fn rem_assign(&mut self, rhs: &Self) {
        unsafe {
            let scratch_size = gmp::mpn_sec_div_r_itch(self.supposed_size, rhs.supposed_size)
                as usize
                * GMP_NUMB_BITS as usize
                / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_div_r(
                    self.inner.d.as_mut(),
                    self.supposed_size,
                    rhs.inner.d.as_ptr(),
                    rhs.supposed_size,
                    null_mut(),
                );

                self.inner.size = rhs.inner.size;
                self.supposed_size = rhs.supposed_size;
                return;
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            gmp::mpn_sec_div_r(
                self.inner.d.as_mut(),
                self.supposed_size,
                rhs.inner.d.as_ptr(),
                rhs.supposed_size,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            self.inner.size = rhs.inner.size;
            self.supposed_size = rhs.supposed_size;
        }
    }
}

/// Not a constant-time function: Reveals the actual size of self.
impl ShrAssign<u32> for BigInteger {
    fn shr_assign(&mut self, rhs: u32) {
        assert!(1 <= rhs);
        assert!(rhs as u64 <= GMP_NUMB_BITS - 1);

        unsafe {
            gmp::mpn_rshift(self.inner.d.as_mut(), self.inner.d.as_ptr(), self.inner.size as i64, rhs);
        }
    }
}

/// Not a constant-time function: Reveals the actual size of self.
impl Shr<u32> for &BigInteger {
    type Output = BigInteger;

    fn shr(self, rhs: u32) -> Self::Output {
        assert!(1 <= rhs);
        assert!(rhs as u64 <= GMP_NUMB_BITS - 1);

        let mut result = BigInteger::init(self.supposed_size);

        unsafe {
            gmp::mpn_rshift(result.inner.d.as_mut(), self.inner.d.as_ptr(), self.inner.size as i64, rhs);
        }

        result.inner.size = self.inner.size;
        result
    }
}

impl PartialEq for BigInteger {
    fn eq(&self, other: &Self) -> bool {
        println!("{} =?= {}", self, other);
        unsafe { gmp::mpz_cmp(&self.inner, &other.inner) == 0 }
    }
}

impl Clone for BigInteger {
    fn clone(&self) -> Self {
        let mut result = BigInteger::init(self.supposed_size);
        
        unsafe {
            mpz_set(&mut result.inner, &self.inner);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use scicrypt_traits::randomness::GeneralRng;

    use crate::bigint::GMP_NUMB_BITS;

    use super::BigInteger;

    #[test]
    fn test_zero() {
        let integer = BigInteger::zero(1024);
        assert!(integer.is_zero());
    }

    #[test]
    fn test_random_not_same() {
        let mut rng = GeneralRng::new(OsRng);

        let a = BigInteger::random(64, &mut rng);
        let b = BigInteger::random(64, &mut rng);
        
        assert_ne!(a, b);
    }

    #[test]
    fn test_random_length_1024() {
        let mut rng = GeneralRng::new(OsRng);

        let a = BigInteger::random(1024, &mut rng);
        
        assert_eq!(a.inner.size, 1024 / GMP_NUMB_BITS as i32);
    }

    #[test]
    fn test_small_number() {
        let integer = BigInteger::new(15, 128);
        assert_eq!(15, integer.get_u64());
    }

    #[test]
    fn test_clone() {
        let mut a = BigInteger::new(15, 128);
        let b = a.clone();

        a += &b;

        assert_eq!(30, a.get_u64()); 
        assert_eq!(15, b.get_u64());
    }

    #[test]
    fn test_add_assign() {
        let mut a = BigInteger::new(123, 128);
        let b = BigInteger::new(256, 128);

        a += &b;

        assert_eq!(379, a.get_u64());
    }

    #[test]
    fn test_shift_right_assign() {
        // TODO: Sometimes fails when run in conjunction!
        let mut a = BigInteger::new(129, 128);
        a >>= 3;

        assert_eq!(16, a.get_u64());
    }

    #[test]
    fn test_modulo() {
        let mut a = BigInteger::new(23, 128);
        let m = BigInteger::new(14, 128);

        a %= &m;

        assert_eq!(9, a.get_u64());
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
    fn test_powmod() {
        let b = BigInteger::new(105, 1024);
        let e = BigInteger::from_string("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
        let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        let res = b.pow_mod(&e, &m);

        let expected = BigInteger::from_string("93381698043531945590460734835437626929406390544089092303961497613088223192062266567807404255983003371786424645697784253062005750244340967243067126193405796382070980127325598311265307429963380264226672935938163271489566200721235534991781171263956580735259196276780705026850011214281556290838394235159210861122".to_string(), 10, 1024);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_powmod_small() {
        let b = BigInteger::new(3, 64);
        let e = BigInteger::new(2, 64);
        let m = BigInteger::new(13, 64);

        let res = b.pow_mod(&e, &m);

        assert_eq!(9, res.get_u64());
    }

    #[test]
    fn test_invert() {
        let a = BigInteger::new(105, 1024);
        let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        let res = a.invert(&m);

        // TODO: Check if this is indeed ok
        let expected = BigInteger::from_string("84061432772340049689808300572413804491980902452673572181446234118442836235303840047558458585418773732980835189507058483169654138942329892232060616703594495557549972465137451136838296148977835528603609908967192656850056541089466756048898473852013665061464617240039941352711244487425431931673569255971479254798".to_string(), 10, 1024);
        assert_eq!(res.unwrap(), expected);
    }

    #[test]
    fn test_invert_small() {
        let a = BigInteger::new(3, 64);
        let m = BigInteger::new(13, 64);

        let res = a.invert(&m);

        assert_eq!(9, res.unwrap().get_u64());
    }

    #[test]
    fn test_no_inverse_small() {
        let a = BigInteger::new(14, 64);
        let m = BigInteger::new(49, 64);

        let res = a.invert(&m);

        assert!(res.is_none());
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_powmod_invalid_sizes() {
        let b = BigInteger::new(1234, 128);
        let e = BigInteger::new(23456, 128);
        let m = BigInteger::new(999331, 128);

        b.pow_mod(&e, &m);
    }
}
