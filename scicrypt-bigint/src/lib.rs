#![feature(int_roundings)]
#![feature(test)]
use std::{ops::{AddAssign, Mul, RemAssign, Rem, Add, ShrAssign, Shr, DivAssign, MulAssign, SubAssign}, cmp::{max, min}, mem::MaybeUninit, ffi::{CString, CStr}, fmt::{Display, Debug}, ptr::null_mut, alloc::Layout};

use gmp_mpfr_sys::gmp::{mpz_t, self};

const ALIGN: usize = 128;
const GMP_NUMB_BITS: u64 = 64;

impl Display for BigInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            if self.is_zero() {
                return f.pad_integral(true, "", "0");
            }

            let c_buf = gmp::mpz_get_str(null_mut(), 10, &self.value);
            let c_str = CStr::from_ptr(c_buf);
            let str_slice: &str = c_str.to_str().unwrap();
            let str = str_slice.to_owned();
            f.pad_integral(true, "", str.trim_start_matches('0'))
        }
    }
}

impl From<u64> for BigInteger {
    fn from(integer: u64) -> Self {
        let mut res = BigInteger::zero(64);

        unsafe {
            gmp::mpz_set_ui(&mut res.value, integer);
        }

        res
    }
}

impl Debug for BigInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <{} bits>", self, self.size_in_bits)
    }
}

pub struct BigInteger {
    value: mpz_t,
    size_in_bits: i64
}

impl Drop for BigInteger {
    fn drop(&mut self) {
        unsafe {
            gmp::mpz_clear(&mut self.value);
        }
    }
}

impl BigInteger {
    fn init(size_in_limbs: i32) -> Self {
        Self::zero((size_in_limbs as u64 * GMP_NUMB_BITS) as i64)
    }

    pub fn new(integer: u64, size_in_bits: i64) -> Self {
        let mut res = BigInteger::zero(size_in_bits);

        unsafe {
            gmp::mpz_set_ui(&mut res.value, integer);
        }

        res
    }

    /// Creates a BigInteger with value 0. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn zero(size_in_bits: i64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), size_in_bits as u64);
            let z = z.assume_init();
            BigInteger {
                value: z,
                size_in_bits,
            }
        }
    }

    /// Creates a BigInteger from a value given as a `string` in a certain `base`. The `size_in_bits` should not be lower than the actual value encoded.
    pub fn from_string(string: String, base: i32, size_in_bits: i64) -> BigInteger {
        // TODO: debug_assert!() that the size_in_bits is not smaller than the actual value

        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), size_in_bits as u64);
            let mut z = z.assume_init();
            let c_string = CString::new(string).unwrap();
            gmp::mpz_set_str(&mut z, c_string.as_ptr(), base);
            BigInteger {
                value: z,
                size_in_bits
            }
        }
    }

    /// Generates a random number with `bits` bits. `bits` should be a multiple of 8.
    pub fn random<R: SecureRng>(bits: i64, rng: &mut GeneralRng<R>) -> Self {
        debug_assert!((bits % 8) == 0, "`bits` should be a multiple of 8");

        unsafe {
            let mut number = BigInteger::zero(bits);
            let limbs = gmp::mpz_limbs_write(&mut number.value, bits.div_ceil(GMP_NUMB_BITS as i64));
    
            for i in 0isize..bits.div_ceil(GMP_NUMB_BITS as i64) as isize {
                let mut bytes = [0; 8];
                rng.rng().fill_bytes(&mut bytes);
                limbs.offset(i).write(u64::from_be_bytes(bytes));
            }

            number.value.size = bits.div_ceil(GMP_NUMB_BITS as i64) as i32;
            number
        }
    }

    pub fn random_below<R: SecureRng>(limit: &BigInteger, rng: &mut GeneralRng<R>) -> Self {
        // FIXME: This is completely not secure
        BigInteger::random(limit.size_in_bits, rng) % limit
    }

    pub fn set_bit(&mut self, bit_index: u64) {
        unsafe {
            gmp::mpz_setbit(&mut self.value, bit_index);
        }
    }

    pub fn clear_bit(&mut self, bit_index: u64) {
        unsafe {
            gmp::mpz_clrbit(&mut self.value, bit_index);
        }
    }

    /// Computes self modulo a u64 number. This function is not constant-time.
    pub fn mod_u(&self, modulus: u64) -> u64 {
        unsafe {
            gmp::mpz_fdiv_ui(&self.value, modulus)
        }
    }

    /// Returns true when this number is prime. This function is not constant-time. Internally it uses Baille-PSW.
    pub fn is_probably_prime(&self) -> bool {
        unsafe {
            gmp::mpz_probab_prime_p(&self.value, 25) > 0
        }
    }

    /// Returns true if self == 0. This is faster than checking equality.
    pub fn is_zero(&self) -> bool {
        self.value.size == 0
    }

    /// Compute `self` to the power `exponent` modulo an odd `modulus`. The computation takes time that scales with the specified size of the `exponent` and `modulus`.
    pub fn pow_mod(&self, exponent: &BigInteger, modulus: &BigInteger) -> BigInteger {
        debug_assert!(!self.is_zero(), "the base must be larger than 0");
        debug_assert!(!modulus.is_zero(), "the modulus must be larger than 0");
        // TODO: debug_assert!() that the modulus is ODD
        // TODO: debug_assert!() that the exponent's bitsize is smaller than its size_in_bits
        debug_assert!(exponent.size_in_bits > 0, "the exponent must be larger than 0");

        debug_assert_eq!(modulus.size_in_bits as i32, modulus.value.size * GMP_NUMB_BITS as i32, "the modulus' size in bits must be tight with its actual size");

        // TODO: Probably we should also assert that the modulus does not contain less limbs than the other operands

        let mut result = BigInteger::init(modulus.value.size);

        let enb = exponent.size_in_bits as u64;

        unsafe {
            let scratch_size =
                gmp::mpn_sec_powm_itch(self.value.size as i64, enb, modulus.value.size as i64) as usize
                    * GMP_NUMB_BITS as usize
                    / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_powm(
                    result.value.d.as_mut(),
                    self.value.d.as_ptr(),
                    self.value.size as i64,
                    exponent.value.d.as_ptr(),
                    enb,
                    modulus.value.d.as_ptr(),
                    modulus.value.size as i64,
                    null_mut(),
                );

                result.value.size = modulus.value.size;
                return result;
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            gmp::mpn_sec_powm(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                exponent.value.d.as_ptr(),
                enb,
                modulus.value.d.as_ptr(),
                modulus.value.size as i64,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            result.value.size = modulus.value.size;
            result
        }
    }

    /// Computes `self^-1 mod modulus`, taking ownership of `self`. Returns None if no inverse exists. `modulus` must be odd.
    pub fn invert(self, modulus: &BigInteger) -> Option<BigInteger> {
        // TODO: Verify that the input must be smaller than the modulus (is this indeed true?)
        //assert_eq!(self.supposed_size, modulus.supposed_size);
        //self.supposed_size = modulus.inner.size as i64;

        debug_assert_eq!(modulus.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, modulus.value.size, "the modulus' size in bits must match its actual size");
        //debug_assert_eq!(modulus.size_in_bits as i32, modulus.value.size * GMP_NUMB_BITS as i32, "the modulus' size in bits must be tight with its actual size");
        debug_assert_eq!(modulus.size_in_bits, self.size_in_bits, "the modulus must have the same size as self");

        // FIXME: This is not constant-time
        //debug_assert_eq!(modulus.value.size, self.value.size, "the modulus must have the same actual size as self");
        // if self.value.size != modulus.value.size {
        //     self += modulus;
        // }
        debug_assert_eq!(modulus.value.size, self.value.size, "the modulus must have the same actual size as self");

        //self += modulus;

        let mut result = BigInteger::init(modulus.value.size);

        unsafe {
            let scratch_size = gmp::mpn_sec_invert_itch(modulus.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize
                / 8;

            if scratch_size == 0 {
                let is_valid = gmp::mpn_sec_invert(
                    result.value.d.as_mut(),
                    self.value.d.as_ptr(),
                    modulus.value.d.as_ptr(),
                    modulus.value.size as i64,
                    (self.size_in_bits + modulus.size_in_bits) as u64,
                    null_mut(),
                );

                // Check if an inverse exists
                if is_valid == 0 {
                    return None;
                }

                result.value.size = modulus.value.size;
                result.size_in_bits = modulus.size_in_bits;
                return Some(result);
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            let is_valid = gmp::mpn_sec_invert(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                modulus.value.d.as_ptr(),
                modulus.value.size as i64,
                (self.size_in_bits + modulus.size_in_bits) as u64,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            // Check if an inverse exists
            if is_valid == 0 {
                return None;
            }

            result.value.size = modulus.value.size;
            result.size_in_bits = modulus.size_in_bits;
            return Some(result);
        }
    }

    // /// Computes `self^-1 mod modulus`, taking ownership of `self`. Returns None if no inverse exists. `modulus` must be odd.
    // pub fn invert(mut self, modulus: &BigInteger) -> Option<BigInteger> {
    //     //assert_eq!(self.supposed_size, modulus.supposed_size);
    //     //self.supposed_size = modulus.inner.size as i64;

    //     debug_assert_eq!(modulus.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, modulus.value.size, "the modulus' size in bits must match its actual size");
    //     //debug_assert_eq!(modulus.size_in_bits as i32, modulus.value.size * GMP_NUMB_BITS as i32, "the modulus' size in bits must be tight with its actual size");
    //     debug_assert_eq!(modulus.size_in_bits, self.size_in_bits, "the modulus must have the same size as self");

    //     dbg!(&self);
    //     dbg!(&modulus);
    //     // FIXME: This is not constant-time
    //     //debug_assert_eq!(modulus.value.size, self.value.size, "the modulus must have the same actual size as self");
    //     if self.value.size != modulus.value.size {
    //         self += modulus;
    //     }
    //     debug_assert_eq!(modulus.value.size, self.value.size, "the modulus must have the same actual size as self");

    //     //self += modulus;

    //     //let mut result = BigInteger::init(modulus.value.size);

    //     unsafe {
    //         let scratch_size = gmp::mpn_sec_invert_itch(modulus.value.size as i64)
    //             as usize
    //             * GMP_NUMB_BITS as usize
    //             / 8;
    //         dbg!(scratch_size);

    //         if scratch_size == 0 {
    //             let is_valid = gmp::mpn_sec_invert(
    //                 self.value.d.as_mut(),
    //                 self.value.d.as_ptr(),
    //                 modulus.value.d.as_ptr(),
    //                 modulus.value.size as i64,
    //                 (self.size_in_bits + modulus.size_in_bits) as u64,
    //                 null_mut(),
    //             );

    //             // Check if an inverse exists
    //             if is_valid == 0 {
    //                 return None;
    //             }

    //             // TODO: This can probably be removed
    //             self.value.size = modulus.value.size;
    //             self.size_in_bits = modulus.size_in_bits;
    //             return Some(self);
    //         }

    //         let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
    //         let scratch = std::alloc::alloc(scratch_layout);

    //         let is_valid = gmp::mpn_sec_invert(
    //             self.value.d.as_mut(),
    //             self.value.d.as_ptr(),
    //             modulus.value.d.as_ptr(),
    //             modulus.value.size as i64,
    //             (self.size_in_bits + modulus.size_in_bits) as u64,
    //             scratch as *mut u64,
    //         );

    //         std::alloc::dealloc(scratch, scratch_layout);

    //         // Check if an inverse exists
    //         if is_valid == 0 {
    //             return None;
    //         }

    //         // TODO: This can probably be removed
    //         self.value.size = modulus.value.size;
    //         self.size_in_bits = modulus.size_in_bits;
    //         return Some(self);
    //     }
    // }

    // Computes the least common multiple between self and other. This function is not constant-time.
    pub fn lcm(&self, other: &BigInteger) -> BigInteger {
        let mut result = BigInteger::init(self.value.size);

        unsafe {
            gmp::mpz_lcm(&mut result.value, &self.value, &other.value);
        }

        result
    }

    pub fn square(&self) -> BigInteger {
        // TODO: Switch to more efficient squaring function
        self * self
    }
}

impl AddAssign<&BigInteger> for BigInteger {
    fn add_assign(&mut self, rhs: &Self) {
        let n = min(self.value.size, rhs.value.size);

        if n == 0 {
            return;
        }

        unsafe {
            let carry = gmp::mpn_add_n(
                self.value.d.as_mut(),
                self.value.d.as_ptr(),
                rhs.value.d.as_ptr(),
                n as i64,
            );

            let largest_size = max(self.value.size, rhs.value.size) as i32;

            self.value.size = largest_size + carry as i32;
            self.size_in_bits = max(self.size_in_bits, rhs.size_in_bits) + carry as i64;
        }
    }
}

impl Add<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

// TODO: Also implement addition with u64 using `mpn_sec_add_1`

impl Mul for &BigInteger {
    type Output = BigInteger;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.value.size > self.value.size {
            return rhs * self;
        }

        debug_assert_eq!(self.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, self.value.size, "the operands' size in bits must match their actual size");
        debug_assert_eq!(rhs.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, rhs.value.size, "the operands' size in bits must match their actual size");

        let mut result = BigInteger::init(self.value.size + rhs.value.size);

        unsafe {
            let scratch_size = gmp::mpn_sec_mul_itch(self.value.size as i64, rhs.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize
                / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_mul(
                    result.value.d.as_mut(),
                    self.value.d.as_ptr(),
                    self.value.size as i64,
                    rhs.value.d.as_ptr(),
                    rhs.value.size as i64,
                    null_mut(),
                );

                result.value.size = self.value.size + rhs.value.size;
                result.size_in_bits = self.size_in_bits + rhs.size_in_bits;
                return result;
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            gmp::mpn_sec_mul(
                result.value.d.as_mut(),
                self.value.d.as_ptr(),
                self.value.size as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            result.value.size = self.value.size + rhs.value.size;
            result.size_in_bits = self.size_in_bits + rhs.size_in_bits;
            result
        }
    }
}

impl DivAssign<&BigInteger> for BigInteger {
    fn div_assign(&mut self, rhs: &BigInteger) {
        todo!()
    }
}

impl SubAssign<&BigInteger> for BigInteger {
    fn sub_assign(&mut self, rhs: &BigInteger) {
        todo!()
    }
}

/// Note that equality checks are not in constant time. This function only considers the number of limbs of the number with the fewest limbs.
impl PartialEq for BigInteger {
    fn eq(&self, other: &Self) -> bool {
        let n = min(self.value.size, other.value.size);
        
        unsafe { gmp::mpn_cmp(self.value.d.as_ptr(), other.value.d.as_ptr(), n as i64) == 0 }
    }
}

impl Eq for BigInteger {
    
}

impl RemAssign<&BigInteger> for BigInteger {
    fn rem_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, self.value.size, "the operands' size in bits must match their actual size");
        debug_assert_eq!(rhs.size_in_bits.div_ceil(GMP_NUMB_BITS as i64) as i32, rhs.value.size, "the operands' size in bits must match their actual size");

        unsafe {
            let scratch_size = gmp::mpn_sec_div_r_itch(self.value.size as i64, rhs.value.size as i64)
                as usize
                * GMP_NUMB_BITS as usize
                / 8;

            if scratch_size == 0 {
                gmp::mpn_sec_div_r(
                    self.value.d.as_mut(),
                    self.value.size as i64,
                    rhs.value.d.as_ptr(),
                    rhs.value.size as i64,
                    null_mut(),
                );

                self.value.size = rhs.value.size;
                self.size_in_bits = rhs.size_in_bits;
                return;
            }

            let scratch_layout = Layout::from_size_align(scratch_size, ALIGN).unwrap();
            let scratch = std::alloc::alloc(scratch_layout);

            gmp::mpn_sec_div_r(
                self.value.d.as_mut(),
                self.value.size as i64,
                rhs.value.d.as_ptr(),
                rhs.value.size as i64,
                scratch as *mut u64,
            );

            std::alloc::dealloc(scratch, scratch_layout);

            self.value.size = rhs.value.size;
            self.size_in_bits = rhs.size_in_bits;
        }
    }
}

impl Rem<&BigInteger> for BigInteger {
    type Output = BigInteger;

    fn rem(mut self, rhs: &BigInteger) -> Self::Output {
        self %= rhs;
        self
    }
}

/// Not a constant-time function: Reveals the actual size of self.
impl ShrAssign<u32> for BigInteger {
    fn shr_assign(&mut self, rhs: u32) {
        assert!(1 <= rhs);
        assert!(rhs as u64 <= GMP_NUMB_BITS - 1);

        unsafe {
            gmp::mpn_rshift(self.value.d.as_mut(), self.value.d.as_ptr(), self.value.size as i64, rhs);
        }
    }
}

/// Not a constant-time function: Reveals the actual size of self.
impl Shr<u32> for &BigInteger {
    type Output = BigInteger;

    fn shr(self, rhs: u32) -> Self::Output {
        assert!(1 <= rhs);
        assert!(rhs as u64 <= GMP_NUMB_BITS - 1);

        let mut result = BigInteger::init(self.value.size);

        unsafe {
            gmp::mpn_rshift(result.value.d.as_mut(), self.value.d.as_ptr(), self.value.size as i64, rhs);
        }

        result.value.size = self.value.size;
        result
    }
}

impl Clone for BigInteger {
    fn clone(&self) -> Self {
        let mut result = BigInteger::init(self.value.size);
        
        unsafe {
            gmp::mpz_set(&mut result.value, &self.value);
        }

        result.size_in_bits = self.size_in_bits;
        result
    }
}


#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use scicrypt_traits::randomness::GeneralRng;

    use crate::{BigInteger, GMP_NUMB_BITS};

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
        
        assert_eq!(a.value.size, 1024 / GMP_NUMB_BITS as i32);
    }

    #[test]
    fn test_addition() {
        let mut x = BigInteger::from_string("5378239758327583290580573280735".to_string(), 10, 103);
        let y = BigInteger::from_string("49127277414859531000011129".to_string(), 10, 86);

        x += &y;

        assert_eq!(BigInteger::from_string("5378288885604998150111573291864".to_string(), 10, 103), x);
        assert_eq!(x.size_in_bits, 103);
    }

    #[test]
    fn test_shift_right_assign() {
        // TODO: Sometimes fails when run in conjunction!
        let mut a = BigInteger::new(129, 128);
        a >>= 3;

        assert_eq!(BigInteger::from(16), a);
    }

    #[test]
    fn test_mul_equal_size() {
        let a = BigInteger::new(23, 64);
        let b = BigInteger::new(14, 64);

        let c = &a * &b;

        assert_eq!(BigInteger::from(23 * 14), c);
    }

    #[test]
    fn test_mul_larger_a() {
        let a = BigInteger::from_string("125789402190859323905892".to_string(), 10, 128);
        let b = BigInteger::new(102, 7);

        let c = &a * &b;

        assert_eq!(BigInteger::from_string("12830519023467651038400984".to_string(), 10, 128), c);
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
    fn test_powmod_small_base() {
        let b = BigInteger::from_string("105".to_string(), 10, 7);
        let e = BigInteger::from_string("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
        let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        let res = b.pow_mod(&e, &m);

        let expected = BigInteger::from_string("93381698043531945590460734835437626929406390544089092303961497613088223192062266567807404255983003371786424645697784253062005750244340967243067126193405796382070980127325598311265307429963380264226672935938163271489566200721235534991781171263956580735259196276780705026850011214281556290838394235159210861122".to_string(), 10, 1024);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_powmod_small_base_oversized() {
        let b = BigInteger::from_string("105".to_string(), 10, 1024);
        let e = BigInteger::from_string("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
        let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        let res = b.pow_mod(&e, &m);

        let expected = BigInteger::from_string("93381698043531945590460734835437626929406390544089092303961497613088223192062266567807404255983003371786424645697784253062005750244340967243067126193405796382070980127325598311265307429963380264226672935938163271489566200721235534991781171263956580735259196276780705026850011214281556290838394235159210861122".to_string(), 10, 1024);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_powmod_small_exponent() {
        let b = BigInteger::from_string("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
        let e = BigInteger::from_string("105".to_string(), 10, 7);
        let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        let res = b.pow_mod(&e, &m);

        // TODO: Validate this number
        let expected = BigInteger::from_string("75449268817968422679819900589734348654486644392551728445064418436053449491480437746932914650717830240874061893534937751643365068436165993034818308531811356620889371580247889632561792360083344802209721380578912179116118493677119654295291184624591629851342172735975592027041999972633543293770666292467255672690".to_string(), 10, 1024);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_powmod_mini() {
        let b = BigInteger::from(3);
        let e = BigInteger::from(7);
        let m = BigInteger::from(11);

        let res = b.pow_mod(&e, &m);

        // TODO: Validate this number
        let expected = BigInteger::from_string("9".to_string(), 10, 1024);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_powmod_mini_plusmod() {
        let b = BigInteger::from(14);
        let e = BigInteger::from(7);
        let m = BigInteger::from(11);

        let res = b.pow_mod(&e, &m);

        // TODO: Validate this number
        let expected = BigInteger::from_string("9".to_string(), 10, 1024);
        assert_eq!(res, expected);
    }

    // #[test]
    // fn test_invert_small_a() {
    //     let mut a = BigInteger::from_string("105".to_string(), 10, 1024);
    //     let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     a += &m;
    //     let res = a.invert(&m);

    //     // TODO: Check if this is indeed ok
    //     let expected = BigInteger::from_string("84061432772340049689808300572413804491980902452673572181446234118442836235303840047558458585418773732980835189507058483169654138942329892232060616703594495557549972465137451136838296148977835528603609908967192656850056541089466756048898473852013665061464617240039941352711244487425431931673569255971479254798".to_string(), 10, 1024);
    //     assert_eq!(res.unwrap(), expected);
    // }

    #[test]
    fn test_invert() {
        let a = BigInteger::from_string("5892358416859326896589748197812740739507917092740973905700591759793209771117197329023975932757523759072735959723097537209079532975039297099714397901428947253853027537265853823285397084380934928703270590758520818187287349487329243789243783249743289423789918417987091287932757258397104397295856325791091077".to_string(), 10, 1024);
        let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        let res = a.invert(&m);

        // TODO: Check if this is indeed ok
        let expected = BigInteger::from_string("123739905086158212270843051527441649600807330749471895683394889028867514801710371562360352272055594352035190616471030275978939424413601977497555131069474726813170115491482106601865630839838144362329125370518957163898801175903502017426241817312333816497160685389024867847545777202327273987093691380956370608950".to_string(), 10, 1024);
        assert_eq!(res.unwrap(), expected);
    }

    #[test]
    fn test_invert_small() {
        let a = BigInteger::from(3);
        let m = BigInteger::from(13);

        let res = a.invert(&m);

        assert_eq!(BigInteger::from(9), res.unwrap());
    }

    #[test]
    fn test_no_inverse_small() {
        let a = BigInteger::from(14);
        let m = BigInteger::from(49);

        let res = a.invert(&m);

        assert!(res.is_none());
    }

    #[test]
    fn test_modulo_assign() {
        let mut a = BigInteger::new(23, 64);
        let m = BigInteger::new(14, 64);

        a %= &m;
        assert_eq!(BigInteger::from(9), a);
    }

    #[test]
    fn test_modulo() {
        let a = BigInteger::new(23, 64);
        let m = BigInteger::new(14, 64);

        assert_eq!(BigInteger::from(9), a % &m);
    }
}

extern crate test;
use scicrypt_traits::randomness::{SecureRng, GeneralRng};
use test::Bencher;

#[bench]
fn bench_powmod_small_base(bench: &mut Bencher) {
    let b = BigInteger::from_string("105".to_string(), 10, 7);
    let e = BigInteger::from_string("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    bench.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(b.pow_mod(&e, &m));
    });
}

#[bench]
fn bench_powmod_large_base(bench: &mut Bencher) {
    let b = BigInteger::from_string("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 1024);
    let e = BigInteger::from_string("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    bench.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(b.pow_mod(&e, &m));
    });
}

#[bench]
fn bench_powmod_large_exp(bench: &mut Bencher) {
    let b = BigInteger::from_string("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 7);
    let e = BigInteger::from_string("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    bench.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(b.pow_mod(&e, &m));
    });
}

#[bench]
fn bench_powmod_small_exp(bench: &mut Bencher) {
    let b = BigInteger::from_string("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 1024);
    let e = BigInteger::from_string("105".to_string(), 10, 1024);
    let m = BigInteger::from_string("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    bench.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(b.pow_mod(&e, &m));
    });
}
