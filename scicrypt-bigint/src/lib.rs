//#![feature(int_roundings)]
#![feature(test)]
#![warn(missing_docs, unused_imports)]
#![feature(array_zip)]
//#![feature(generic_const_exprs)]

//! _This is a part of **scicrypt**. For more information, head to the
//! [scicrypt](https://crates.io/crates/scicrypt) crate homepage._
//!
//! This crate implements a `BigInteger`, for which most arithmetic operations take a constant amount of time given the specified sizes. This crate is nothing more than a convenient wrapper around the low-level constant-time functions from GMP.

mod scratch;

mod arithmetic;
mod binary;
mod modular;

use std::{
    cmp::{min, Ordering, max},
    ffi::{CStr, CString},
    fmt::{Debug, Display},
    hash::Hash,
    ptr::null_mut,
};

use scicrypt_traits::randomness::{GeneralRng, SecureRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{ConditionallySelectable, Choice};
use rug::Integer;

impl<const LIMB_COUNT: usize> From<u64> for UnsignedInteger<LIMB_COUNT> {
    fn from(integer: u64) -> Self {
        let mut limbs = [0; LIMB_COUNT];
        limbs[0] = integer;
        UnsignedInteger {
            limbs,
            occupied_limbs: 1
        }
    }
}

// TODO: Rename to CtInteger (constant-time integer)
/// An unsigned big integer. The integer can only grow up to size `LIMB_COUNT`. Unless specified with the `leaky` keyword, all functions are designed to be constant-time.
#[derive(Debug, Eq, Clone, Copy, Ord, Hash)]
pub struct UnsignedInteger<const LIMB_COUNT: usize> {
    limbs: [u64; LIMB_COUNT],
    occupied_limbs: usize,
}

type U1024 = UnsignedInteger<16>;
type U2048 = UnsignedInteger<32>;
type U3072 = UnsignedInteger<48>;

unsafe impl<const LIMB_COUNT: usize> Send for UnsignedInteger<LIMB_COUNT> {}

impl<const LIMB_COUNT: usize> From<Integer> for UnsignedInteger<LIMB_COUNT> {
    fn from(leaky_integer: Integer) -> Self {
        let leaky_limbs = leaky_integer.as_limbs();

        assert!(leaky_limbs.len() <= LIMB_COUNT);

        let mut limbs = [0; LIMB_COUNT];
        for i in 0..leaky_limbs.len() {
            limbs[i] = leaky_limbs[i];
        }

        UnsignedInteger {
            limbs,
            occupied_limbs: leaky_limbs.len(),
        }
    }
}

// TODO: Make serde optional, but always enable rug along with it.
// impl Serialize for UnsignedInteger {
//     fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         self.clone().to_rug().serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for UnsignedInteger {
//     fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<UnsignedInteger, D::Error> {
//         let integer = Integer::deserialize(deserializer)?;
//         Ok(UnsignedInteger::from(integer))
//     }
// }

impl<const LIMB_COUNT: usize> UnsignedInteger<LIMB_COUNT> {
    // /// Creates a new `UnsignedInteger` that equals `value` with the given number of limbs.
    // pub fn from_u64(value: u64) -> Self {
    //     let mut limbs = [0; LIMB_COUNT];
    //     limbs[0] = value;
    //     UnsignedInteger {
    //         limbs,
    //         occupied_limbs: 1
    //     }
    // }

    /// Creates a BigInteger with value 0. All arithmetic operations are constant-time with regards to the integer's size.
    pub fn zero() -> UnsignedInteger<LIMB_COUNT> {
        UnsignedInteger {
            limbs: [0; LIMB_COUNT],
            occupied_limbs: 0
        }
    }

    /// Creates an UnsignedInteger from a value given as a `string` in a certain `base`. Panics if an error occurs.
    pub fn from_str_leaky(string: &str, base: i32) -> UnsignedInteger<LIMB_COUNT> {
        Integer::from_str_radix(string, base).unwrap().into()
    }

    // /// Generates a random unsigned number with `bits` bits. `bits` should be a multiple of 8.
    // pub fn random<R: SecureRng>(bits: u32, rng: &mut GeneralRng<R>) -> Self {
    //     // TODO: Change bits to bytes to make this API safer
    //     debug_assert!((bits % 8) == 0, "`bits` should be a multiple of 8");

    //     unsafe {
    //         let mut number = UnsignedInteger::zero(bits);
    //         let limbs =
    //             gmp::mpz_limbs_write(&mut number.value, bits.div_ceil(GMP_NUMB_BITS) as i64);

    //         for i in 0isize..bits.div_ceil(GMP_NUMB_BITS) as isize {
    //             let mut bytes = [0; 8];
    //             rng.rng().fill_bytes(&mut bytes);
    //             limbs.offset(i).write(u64::from_be_bytes(bytes));
    //         }

    //         number.value.size = bits.div_ceil(GMP_NUMB_BITS) as i32;
    //         number
    //     }
    // }

    // /// Generates a random unsigned number below `limit`.
    // pub fn random_below<R: SecureRng>(limit: &UnsignedInteger, rng: &mut GeneralRng<R>) -> Self {
    //     // Simple rejection sampling, not constant_time
    //     loop {
    //         let random = UnsignedInteger::random(limit.size_in_bits, rng);

    //         if random.leak() < limit.leak() {
    //             break random;
    //         }
    //     }
    // }

    // /// Sets the bit at `bit_index` to 1. This function is not constant-time.
    // pub fn set_bit_leaky(&mut self, bit_index: u32) {
    //     unsafe {
    //         gmp::mpz_setbit(&mut self.value, bit_index as u64);
    //     }
    // }

    // /// Sets the bit at `bit_index` to 0. This function is not constant-time.
    // pub fn clear_bit_leaky(&mut self, bit_index: u32) {
    //     unsafe {
    //         gmp::mpz_clrbit(&mut self.value, bit_index as u64);
    //     }
    // }

    // /// Computes self modulo a u64 number. This function is not constant-time.
    // pub fn mod_u_leaky(&self, modulus: u64) -> u64 {
    //     unsafe { gmp::mpz_fdiv_ui(&self.value, modulus) }
    // }

    // /// Returns true when this number is prime. This function is not constant-time. Internally it uses Baille-PSW.
    // pub fn is_probably_prime_leaky(&self) -> bool {
    //     unsafe { gmp::mpz_probab_prime_p(&self.value, 25) > 0 }
    // }

    // /// Returns true if self == 0. This can be faster than checking equality.
    // pub fn is_zero_leaky(&self) -> bool {
    //     if self.value.size == 0 {
    //         return true;
    //     }

    //     for i in 0..self.value.size {
    //         unsafe {
    //             if *self.value.d.as_ptr().offset(i as isize) != 0 {
    //                 return false;
    //             }
    //         }
    //     }

    //     true
    // }

    // /// Computes the least common multiple between self and other. This function is not constant-time.
    // pub fn lcm_leaky(&self, other: &UnsignedInteger) -> UnsignedInteger {
    //     let mut result = UnsignedInteger::init(self.value.size);

    //     unsafe {
    //         gmp::mpz_lcm(&mut result.value, &self.value, &other.value);
    //     }

    //     result.size_in_bits = (result.value.size * GMP_NUMB_BITS as i32) as u32;
    //     result
    // }

    // /// Computes $n!$. This function is not constant-time.
    // pub fn factorial_leaky(n: u64) -> Self {
    //     let mut res = UnsignedInteger::init(0);

    //     unsafe {
    //         mpz_fac_ui(&mut res.value, n);
    //     }

    //     res.size_in_bits = (res.value.size * GMP_NUMB_BITS as i32) as u32;
    //     res
    // }

    // TODO: Replace reduce_leaky with to_leaky.
    // /// Reduces `self` so that there are no leading zero-limbs. In other words, the representation becomes as small as possible to represent this value. This leaks the actual size of the encoded value.
    // pub fn reduce_leaky(&mut self) {
    //     loop {
    //         if self.limbs[self.occupied_limbs - 1] != 0 {
    //             break;
    //         }

    //         self.occupied_limbs -= 1;
    //     }
    // }
}

impl<const LIMB_COUNT: usize> PartialEq for UnsignedInteger<LIMB_COUNT> {
    fn eq(&self, other: &Self) -> bool {
        let occupied_limbs = max(self.occupied_limbs, other.occupied_limbs);
        let mut result = 0;

        for i in 0..occupied_limbs {
            result |= self.limbs[i] ^ other.limbs[i];
        }

        result == 0
    }
}

impl<const LIMB_COUNT: usize> PartialOrd for UnsignedInteger<LIMB_COUNT> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let occupied_limbs = max(self.occupied_limbs, other.occupied_limbs);
        let mut result = Ordering::Equal;

        for i in 0..occupied_limbs {
            if self.limbs[i] < other.limbs[i] {
                result = Ordering::Less;
            }
            if self.limbs[i] > other.limbs[i] {
                result = Ordering::Greater;
            }
        }

        Some(result)
    }
}

impl<const LIMB_COUNT: usize> ConditionallySelectable for UnsignedInteger<LIMB_COUNT> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        UnsignedInteger {
            limbs: a.limbs.zip(b.limbs).map(|(al, bl)| u64::conditional_select(&al, &bl, choice.clone())),
            occupied_limbs: u64::conditional_select(&(a.occupied_limbs as u64), &(b.occupied_limbs as u64), choice) as usize
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

    use crate::UnsignedInteger;

    extern crate test;
    use test::Bencher;

    // #[bench]
    // fn bench_powmod_small_base(bench: &mut Bencher) {
    //     let b = UnsignedInteger::from_string_leaky("105".to_string(), 10, 7);
    //     let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     bench.iter(|| {
    //         // Use `test::black_box` to prevent compiler optimizations from disregarding
    //         // Unused values
    //         test::black_box(b.pow_mod(&e, &m));
    //     });
    // }

    // #[bench]
    // fn bench_powmod_large_base(bench: &mut Bencher) {
    //     let b = UnsignedInteger::from_string_leaky("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 1024);
    //     let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     bench.iter(|| {
    //         // Use `test::black_box` to prevent compiler optimizations from disregarding
    //         // Unused values
    //         test::black_box(b.pow_mod(&e, &m));
    //     });
    // }

    // #[bench]
    // fn bench_powmod_large_exp(bench: &mut Bencher) {
    //     let b = UnsignedInteger::from_string_leaky("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 7);
    //     let e = UnsignedInteger::from_string_leaky("92848022024833655041372304737256052921065477715975001419347548380734496823522565044177931242947122534563813415992433917108481569319894167972639736788613656007853719476736625612543893748136536594494005487213485785676333621181690463942417781763743640447405597892807333854156631166426238815716390011586838580891".to_string(), 10, 1024);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     bench.iter(|| {
    //         // Use `test::black_box` to prevent compiler optimizations from disregarding
    //         // Unused values
    //         test::black_box(b.pow_mod(&e, &m));
    //     });
    // }

    // #[bench]
    // fn bench_powmod_small_exp(bench: &mut Bencher) {
    //     let b = UnsignedInteger::from_string_leaky("10539499294995885839929294349858893482048503424233434382948939585380202480248428858035020202848894983349030959432221114892829832832820310342164784362849732894729586478637897481742109741907489237586753826748420497102914324234241221888888487774774646263775738582835875726672378181992949120102959881821".to_string(), 10, 1024);
    //     let e = UnsignedInteger::from_string_leaky("105".to_string(), 10, 1024);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     bench.iter(|| {
    //         // Use `test::black_box` to prevent compiler optimizations from disregarding
    //         // Unused values
    //         test::black_box(b.pow_mod(&e, &m));
    //     });
    // }

    #[test]
    fn test_hash_eq() {
        let a = UnsignedInteger::<10>::from(123u64);
        let b = UnsignedInteger::<10>::from(123u64);

        let mut hasher_a = DefaultHasher::new();
        a.hash(&mut hasher_a);

        let mut hasher_b = DefaultHasher::new();
        b.hash(&mut hasher_b);

        assert_eq!(hasher_a.finish(), hasher_b.finish())
    }

    #[test]
    fn test_hash_neq() {
        let a = UnsignedInteger::<10>::from(123u64);
        let b = UnsignedInteger::<10>::from(124u64);

        let mut hasher_a = DefaultHasher::new();
        a.hash(&mut hasher_a);

        let mut hasher_b = DefaultHasher::new();
        b.hash(&mut hasher_b);

        assert_ne!(hasher_a.finish(), hasher_b.finish())
    }

    // #[test]
    // fn test_random_not_same() {
    //     let mut rng = GeneralRng::new(OsRng);

    //     let a = UnsignedInteger::random(64, &mut rng);
    //     let b = UnsignedInteger::random(64, &mut rng);

    //     assert_ne!(a, b);
    // }

    // #[test]
    // fn test_random_length_1024() {
    //     let mut rng = GeneralRng::new(OsRng);

    //     let a = UnsignedInteger::random(1024, &mut rng);

    //     assert_eq!(a.value.size, 1024 / GMP_NUMB_BITS as i32);
    // }

    // #[test]
    // fn test_shift_right_assign() {
    //     let mut a = UnsignedInteger::new(129, 128);
    //     a >>= 3;

    //     assert_eq!(UnsignedInteger::from(16u64), a);
    // }

    // #[test]
    // fn test_factorial() {
    //     let a = UnsignedInteger::factorial_leaky(9);
    //     let b = UnsignedInteger::from_string_leaky("87178291200".to_string(), 10, 37);

    //     assert_ne!(a, b);
    // }

    // #[test]
    // fn test_factorial_large() {
    //     let a = UnsignedInteger::factorial_leaky(21);
    //     let b = UnsignedInteger::from_string_leaky("51090942171709440000".to_string(), 10, 66);

    //     assert_eq!(a, b);
    // }

    // #[test]
    // fn test_invert() {
    //     let a = UnsignedInteger::from_string_leaky("5892358416859326896589748197812740739507917092740973905700591759793209771117197329023975932757523759072735959723097537209079532975039297099714397901428947253853027537265853823285397084380934928703270590758520818187287349487329243789243783249743289423789918417987091287932757258397104397295856325791091077".to_string(), 10, 1024);
    //     let m = UnsignedInteger::from_string_leaky("149600854933825512159828331527177109689118555212385170831387365804008437367913613643959968668965614270559113472851544758183282789643129469226548555150464780229538086590498853718102052468519876788192865092229749643546710793464305243815836267024770081889047200172952438000587807986096107675012284269101785114471".to_string(), 10, 1024);

    //     let res = a.invert(&m);

    //     let expected = UnsignedInteger::from_string_leaky("123739905086158212270843051527441649600807330749471895683394889028867514801710371562360352272055594352035190616471030275978939424413601977497555131069474726813170115491482106601865630839838144362329125370518957163898801175903502017426241817312333816497160685389024867847545777202327273987093691380956370608950".to_string(), 10, 1024);
    //     assert_eq!(res.unwrap(), expected);
    // }

    // #[test]
    // fn test_invert_small() {
    //     let a = UnsignedInteger::from(3u64);
    //     let m = UnsignedInteger::from(13u64);

    //     let res = a.invert(&m);

    //     assert_eq!(UnsignedInteger::from(9u64), res.unwrap());
    // }

    // #[test]
    // fn test_no_inverse_small() {
    //     let a = UnsignedInteger::from(14u64);
    //     let m = UnsignedInteger::from(49u64);

    //     let res = a.invert(&m);

    //     assert!(res.is_none());
    // }
}
