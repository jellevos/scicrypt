#![feature(int_roundings)]
#![feature(test)]
#![warn(missing_docs, unused_imports)]

//! _This is a part of **scicrypt**. For more information, head to the
//! [scicrypt](https://crates.io/crates/scicrypt) crate homepage._
//!
//! This crate implements a `BigInteger`, for which most arithmetic operations take a constant amount of time given the specified sizes. This crate is nothing more than a convenient wrapper around the low-level constant-time functions from GMP.

mod scratch;

mod arithmetic;
mod binary;
mod leaky_ops;
mod modular;

use std::{
    cmp::min,
    ffi::{CStr, CString},
    fmt::{Debug, Display},
    hash::Hash,
    mem::{ManuallyDrop, MaybeUninit},
    ptr::null_mut,
};

use gmp_mpfr_sys::gmp::{self, mpz_fac_ui, mpz_t};

#[cfg(feature = "rug")]
use rug::Integer;
use scicrypt_traits::randomness::{GeneralRng, SecureRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const GMP_NUMB_BITS: u32 = 64;

impl Display for UnsignedInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            if self.is_zero_leaky() {
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

impl From<u64> for UnsignedInteger {
    fn from(integer: u64) -> Self {
        let mut res = UnsignedInteger::zero(64 - integer.leading_zeros());

        unsafe {
            gmp::mpz_set_ui(&mut res.value, integer);
        }

        res
    }
}

#[cfg(feature = "rug")]
impl From<Integer> for UnsignedInteger {
    fn from(integer: Integer) -> Self {
        debug_assert!(integer >= 0);
        let size_in_bits = integer.significant_bits();
        UnsignedInteger {
            value: integer.into_raw(),
            size_in_bits,
        }
    }
}

#[cfg(feature = "rug")]
impl UnsignedInteger {
    /// Transforms this `UnsignedInteger` into a rug `Integer`.
    pub fn to_rug(self) -> Integer {
        let value = self.value;
        let _ = ManuallyDrop::new(self);
        unsafe { Integer::from_raw(value) }
    }
}

impl Debug for UnsignedInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{self} <{} bits as {}x{GMP_NUMB_BITS}-bit limbs>",
            self.size_in_bits, self.value.size
        )
    }
}

/// An unsigned big (arbitrary-size) integer. Unless specified with the `leaky` keyword, all functions are designed to be constant-time.
pub struct UnsignedInteger {
    value: mpz_t,
    size_in_bits: u32,
}

impl Drop for UnsignedInteger {
    fn drop(&mut self) {
        unsafe {
            gmp::mpz_clear(&mut self.value);
        }
    }
}

// TODO: Make serde optional, but always enable rug along with it.
impl Serialize for UnsignedInteger {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.clone().to_rug().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UnsignedInteger {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<UnsignedInteger, D::Error> {
        let integer = Integer::deserialize(deserializer)?;
        Ok(UnsignedInteger::from(integer))
    }
}

impl UnsignedInteger {
    fn init(size_in_limbs: i32) -> Self {
        Self::zero(size_in_limbs.unsigned_abs() * GMP_NUMB_BITS)
    }

    /// The size of the unsiged number expressed in bits. This is a reasonably tight upper bound (it cannot exceed the actual value by more than 64 bits).
    pub fn size_in_bits(&self) -> u32 {
        self.size_in_bits
    }

    /// Creates a new `UnsignedInteger` that equals `integer` with the given `size_in_bits`. `size_in_bits` must be a tight estimate; it may only exceed the actual number of bits until the next multiple of 64.
    pub fn new(integer: u64, size_in_bits: u32) -> Self {
        let mut res = UnsignedInteger::zero(size_in_bits);

        unsafe {
            gmp::mpz_set_ui(&mut res.value, integer);
        }

        res
    }

    /// Creates a BigInteger with value 0. All arithmetic operations are constant-time with regards to the integer's size `bits`.
    pub fn zero(size_in_bits: u32) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), size_in_bits as u64);
            let z = z.assume_init();
            UnsignedInteger {
                value: z,
                size_in_bits,
            }
        }
    }

    /// Creates a BigInteger from a value given as a `string` in a certain `base`. The `size_in_bits` should not be lower than the actual value encoded.
    pub fn from_string_leaky(string: String, base: i32, size_in_bits: u32) -> UnsignedInteger {
        // TODO: debug_assert!() that the size_in_bits is not smaller than the actual value
        debug_assert!(
            !string.starts_with('-'),
            "Only unsigned integers are supported"
        );

        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), size_in_bits as u64);
            let mut z = z.assume_init();
            let c_string = CString::new(string).unwrap();
            gmp::mpz_set_str(&mut z, c_string.as_ptr(), base);
            UnsignedInteger {
                value: z,
                size_in_bits,
            }
        }
    }

    /// Generates a random unsigned number with `bits` bits. `bits` should be a multiple of 8.
    pub fn random<R: SecureRng>(bits: u32, rng: &mut GeneralRng<R>) -> Self {
        debug_assert!((bits % 8) == 0, "`bits` should be a multiple of 8");

        unsafe {
            let mut number = UnsignedInteger::zero(bits);
            let limbs =
                gmp::mpz_limbs_write(&mut number.value, bits.div_ceil(GMP_NUMB_BITS) as i64);

            for i in 0isize..bits.div_ceil(GMP_NUMB_BITS) as isize {
                let mut bytes = [0; 8];
                rng.rng().fill_bytes(&mut bytes);
                limbs.offset(i).write(u64::from_be_bytes(bytes));
            }

            number.value.size = bits.div_ceil(GMP_NUMB_BITS) as i32;
            number
        }
    }

    /// Generates a random unsigned number below `limit`.
    pub fn random_below<R: SecureRng>(limit: &UnsignedInteger, rng: &mut GeneralRng<R>) -> Self {
        // Simple rejection sampling, not constant_time
        loop {
            let random = UnsignedInteger::random(limit.size_in_bits, rng);

            if random.leak() < limit.leak() {
                break random;
            }
        }
    }

    /// Sets the bit at `bit_index` to 1. This function is not constant-time.
    pub fn set_bit_leaky(&mut self, bit_index: u32) {
        unsafe {
            gmp::mpz_setbit(&mut self.value, bit_index as u64);
        }
    }

    /// Sets the bit at `bit_index` to 0. This function is not constant-time.
    pub fn clear_bit_leaky(&mut self, bit_index: u32) {
        unsafe {
            gmp::mpz_clrbit(&mut self.value, bit_index as u64);
        }
    }

    /// Computes self modulo a u64 number. This function is not constant-time.
    pub fn mod_u_leaky(&self, modulus: u64) -> u64 {
        unsafe { gmp::mpz_fdiv_ui(&self.value, modulus) }
    }

    /// Returns true when this number is prime. This function is not constant-time. Internally it uses Baille-PSW.
    pub fn is_probably_prime_leaky(&self) -> bool {
        unsafe { gmp::mpz_probab_prime_p(&self.value, 25) > 0 }
    }

    /// Returns true if self == 0. This can be faster than checking equality.
    pub fn is_zero_leaky(&self) -> bool {
        if self.value.size == 0 {
            return true;
        }

        for i in 0..self.value.size {
            unsafe {
                if *self.value.d.as_ptr().offset(i as isize) != 0 {
                    return false;
                }
            }
        }

        true
    }

    /// Computes the least common multiple between self and other. This function is not constant-time.
    pub fn lcm_leaky(&self, other: &UnsignedInteger) -> UnsignedInteger {
        let mut result = UnsignedInteger::init(self.value.size);

        unsafe {
            gmp::mpz_lcm(&mut result.value, &self.value, &other.value);
        }

        result.size_in_bits = (result.value.size * GMP_NUMB_BITS as i32) as u32;
        result
    }

    /// Computes $n!$. This function is not constant-time.
    pub fn factorial_leaky(n: u64) -> Self {
        let mut res = UnsignedInteger::init(0);

        unsafe {
            mpz_fac_ui(&mut res.value, n);
        }

        res.size_in_bits = (res.value.size * GMP_NUMB_BITS as i32) as u32;
        res
    }
}

impl PartialEq for UnsignedInteger {
    fn eq(&self, other: &Self) -> bool {
        let overlap = min(self.value.size, other.value.size) as isize;

        let mut res: u64 = 0;
        unsafe {
            // Compute the XOR between every limb and take the OR of all these comparisons
            for i in 0..overlap {
                res |= *self.value.d.as_ptr().offset(i) ^ *other.value.d.as_ptr().offset(i);
            }

            // If there are limbs left in self, OR them as well
            for i in overlap..self.value.size as isize {
                res |= *self.value.d.as_ptr().offset(i);
            }

            // If there are limbs left in other, OR them as well
            for i in overlap..other.value.size as isize {
                res |= *other.value.d.as_ptr().offset(i);
            }
        }

        res == 0
    }
}

impl Eq for UnsignedInteger {}

impl Clone for UnsignedInteger {
    fn clone(&self) -> Self {
        let mut result = UnsignedInteger::init(self.value.size);

        unsafe {
            gmp::mpz_set(&mut result.value, &self.value);
        }

        result.size_in_bits = self.size_in_bits;
        result
    }
}

impl Hash for UnsignedInteger {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        unsafe {
            for i in 0..self.value.size as isize {
                (*self.value.d.as_ptr().offset(i)).hash(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use rand::rngs::OsRng;
    use scicrypt_traits::randomness::GeneralRng;

    use crate::{UnsignedInteger, GMP_NUMB_BITS};

    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_powmod_small_base(bench: &mut Bencher) {
        let b = UnsignedInteger::from_string_leaky("105".to_string(), 10, 7);
        let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
        let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        bench.iter(|| {
            // Use `test::black_box` to prevent compiler optimizations from disregarding
            // Unused values
            test::black_box(b.pow_mod(&e, &m));
        });
    }

    #[bench]
    fn bench_powmod_large_base(bench: &mut Bencher) {
        let b = UnsignedInteger::from_string_leaky("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 1024);
        let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
        let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        bench.iter(|| {
            // Use `test::black_box` to prevent compiler optimizations from disregarding
            // Unused values
            test::black_box(b.pow_mod(&e, &m));
        });
    }

    #[bench]
    fn bench_powmod_large_exp(bench: &mut Bencher) {
        let b = UnsignedInteger::from_string_leaky("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 7);
        let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
        let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        bench.iter(|| {
            // Use `test::black_box` to prevent compiler optimizations from disregarding
            // Unused values
            test::black_box(b.pow_mod(&e, &m));
        });
    }

    #[bench]
    fn bench_powmod_small_exp(bench: &mut Bencher) {
        let b = UnsignedInteger::from_string_leaky("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 1024);
        let e = UnsignedInteger::from_string_leaky("105".to_string(), 10, 1024);
        let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        bench.iter(|| {
            // Use `test::black_box` to prevent compiler optimizations from disregarding
            // Unused values
            test::black_box(b.pow_mod(&e, &m));
        });
    }

    #[test]
    fn test_hash_eq() {
        let a = UnsignedInteger::from(123u64);
        let b = UnsignedInteger::from(123u64);

        let mut hasher_a = DefaultHasher::new();
        a.hash(&mut hasher_a);

        let mut hasher_b = DefaultHasher::new();
        b.hash(&mut hasher_b);

        assert_eq!(hasher_a.finish(), hasher_b.finish())
    }

    #[test]
    fn test_hash_neq() {
        let a = UnsignedInteger::from(123u64);
        let b = UnsignedInteger::from(124u64);

        let mut hasher_a = DefaultHasher::new();
        a.hash(&mut hasher_a);

        let mut hasher_b = DefaultHasher::new();
        b.hash(&mut hasher_b);

        assert_ne!(hasher_a.finish(), hasher_b.finish())
    }

    #[test]
    fn test_random_not_same() {
        let mut rng = GeneralRng::new(OsRng);

        let a = UnsignedInteger::random(64, &mut rng);
        let b = UnsignedInteger::random(64, &mut rng);

        assert_ne!(a, b);
    }

    #[test]
    fn test_random_length_1024() {
        let mut rng = GeneralRng::new(OsRng);

        let a = UnsignedInteger::random(1024, &mut rng);

        assert_eq!(a.value.size, 1024 / GMP_NUMB_BITS as i32);
    }

    #[test]
    fn test_shift_right_assign() {
        let mut a = UnsignedInteger::new(129, 128);
        a >>= 3;

        assert_eq!(UnsignedInteger::from(16u64), a);
    }

    #[test]
    fn test_factorial() {
        let a = UnsignedInteger::factorial_leaky(9);
        let b = UnsignedInteger::from_string_leaky("87178291200".to_string(), 10, 37);

        assert_ne!(a, b);
    }

    #[test]
    fn test_factorial_large() {
        let a = UnsignedInteger::factorial_leaky(21);
        let b = UnsignedInteger::from_string_leaky("51090942171709440000".to_string(), 10, 66);

        assert_eq!(a, b);
    }

    #[test]
    fn test_invert() {
        let a = UnsignedInteger::from_string_leaky("5892358416859326896589748197812740739507917092740973905700591759793209771117197329023975932757523759072735959723097537209079532975039297099714397901428947253853027537265853823285397084380934928703270590758520818187287349487329243789243783249743289423789918417987091287932757258397104397295856325791091077".to_string(), 10, 1024);
        let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

        let res = a.invert(&m);

        let expected = UnsignedInteger::from_string_leaky("123739905086158212270843051527441649600807330749471895683394889028867514801710371562360352272055594352035190616471030275978939424413601977497555131069474726813170115491482106601865630839838144362329125370518957163898801175903502017426241817312333816497160685389024867847545777202327273987093691380956370608950".to_string(), 10, 1024);
        assert_eq!(res.unwrap(), expected);
    }

    #[test]
    fn test_invert_small() {
        let a = UnsignedInteger::from(3u64);
        let m = UnsignedInteger::from(13u64);

        let res = a.invert(&m);

        assert_eq!(UnsignedInteger::from(9u64), res.unwrap());
    }

    #[test]
    fn test_no_inverse_small() {
        let a = UnsignedInteger::from(14u64);
        let m = UnsignedInteger::from(49u64);

        let res = a.invert(&m);

        assert!(res.is_none());
    }
}
