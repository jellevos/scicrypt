#![feature(int_roundings)]
#![feature(test)]
mod scratch;

mod arithmetic;
mod binary;
mod modular;

use std::{
    cmp::min,
    ffi::{CStr, CString},
    fmt::{Debug, Display},
    mem::MaybeUninit,
    ptr::null_mut,
};

use gmp_mpfr_sys::gmp::{self, mpz_fac_ui, mpz_t};

const GMP_NUMB_BITS: u32 = 64;

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

impl From<i64> for BigInteger {
    fn from(integer: i64) -> Self {
        let mut res = BigInteger::zero(64);

        unsafe {
            gmp::mpz_set_si(&mut res.value, integer);
        }

        res
    }
}

impl Debug for BigInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{self} <{} bits as {}x{GMP_NUMB_BITS}-bit limbs>",
            self.size_in_bits,
            self.value.size.abs()
        )
    }
}

pub struct BigInteger {
    value: mpz_t,
    size_in_bits: u32,
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
        Self::zero(size_in_limbs.abs() as u32 * GMP_NUMB_BITS)
    }

    /// The size of the signed/unsiged numbers expressed in bits. This is a reasonably tight upper bound (it cannot exceed the actual value by more than 64 bits).
    pub fn size_in_bits(&self) -> u32 {
        self.size_in_bits
    }

    pub fn new(integer: u64, size_in_bits: u32) -> Self {
        let mut res = BigInteger::zero(size_in_bits);

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
            BigInteger {
                value: z,
                size_in_bits,
            }
        }
    }

    /// Creates a BigInteger from a value given as a `string` in a certain `base`. The `size_in_bits` should not be lower than the actual value encoded.
    pub fn from_string(string: String, base: i32, size_in_bits: u32) -> BigInteger {
        // TODO: debug_assert!() that the size_in_bits is not smaller than the actual value

        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init2(z.as_mut_ptr(), size_in_bits as u64);
            let mut z = z.assume_init();
            let c_string = CString::new(string).unwrap();
            gmp::mpz_set_str(&mut z, c_string.as_ptr(), base);
            BigInteger {
                value: z,
                size_in_bits,
            }
        }
    }

    /// Generates a random unsigned number with `bits` bits. `bits` should be a multiple of 8.
    pub fn random<R: SecureRng>(bits: u32, rng: &mut GeneralRng<R>) -> Self {
        debug_assert!((bits % 8) == 0, "`bits` should be a multiple of 8");

        unsafe {
            let mut number = BigInteger::zero(bits);
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
    pub fn random_below<R: SecureRng>(limit: &BigInteger, rng: &mut GeneralRng<R>) -> Self {
        // FIXME: This is completely not secure
        BigInteger::random(limit.size_in_bits, rng) % limit
    }

    pub fn set_bit(&mut self, bit_index: u32) {
        unsafe {
            gmp::mpz_setbit(&mut self.value, bit_index as u64);
        }
    }

    pub fn clear_bit(&mut self, bit_index: u32) {
        unsafe {
            gmp::mpz_clrbit(&mut self.value, bit_index as u64);
        }
    }

    /// Computes self modulo a u64 number. This function is not constant-time.
    pub fn mod_u(&self, modulus: u64) -> u64 {
        unsafe { gmp::mpz_fdiv_ui(&self.value, modulus) }
    }

    /// Returns true when this number is prime. This function is not constant-time. Internally it uses Baille-PSW.
    pub fn is_probably_prime(&self) -> bool {
        unsafe { gmp::mpz_probab_prime_p(&self.value, 25) > 0 }
    }

    /// Returns true if self == 0. This is faster than checking equality.
    pub fn is_zero(&self) -> bool {
        self.value.size == 0
    }

    // Computes the least common multiple between self and other. This function is not constant-time.
    pub fn lcm(&self, other: &BigInteger) -> BigInteger {
        let mut result = BigInteger::init(self.value.size);

        unsafe {
            gmp::mpz_lcm(&mut result.value, &self.value, &other.value);
        }

        result.size_in_bits = (result.value.size * GMP_NUMB_BITS as i32) as u32;
        result
    }

    pub fn factorial(n: u64) -> Self {
        let mut res = BigInteger::init(0);

        unsafe {
            mpz_fac_ui(&mut res.value, n);
        }

        res.size_in_bits = (res.value.size * GMP_NUMB_BITS as i32) as u32;
        res
    }
}

/// Note that equality checks are not in constant time. This function only considers the number of limbs of the number with the fewest limbs.
impl PartialEq for BigInteger {
    fn eq(&self, other: &Self) -> bool {
        let n = min(self.value.size.abs(), other.value.size.abs());

        unsafe { gmp::mpn_cmp(self.value.d.as_ptr(), other.value.d.as_ptr(), n as i64) == 0 }
    }
}

impl Eq for BigInteger {}

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
    fn test_shift_right_assign() {
        // TODO: Sometimes fails when run in conjunction!
        let mut a = BigInteger::new(129, 128);
        a >>= 3;

        assert_eq!(BigInteger::from(16u64), a);
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
        let b = BigInteger::from(3u64);
        let e = BigInteger::from(7u64);
        let m = BigInteger::from(11u64);

        let res = b.pow_mod(&e, &m);

        // TODO: Validate this number
        let expected = BigInteger::from_string("9".to_string(), 10, 1024);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_powmod_mini_plusmod() {
        let b = BigInteger::from(14u64);
        let e = BigInteger::from(7u64);
        let m = BigInteger::from(11u64);

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
        let a = BigInteger::from(3u64);
        let m = BigInteger::from(13u64);

        let res = a.invert(&m);

        assert_eq!(BigInteger::from(9u64), res.unwrap());
    }

    #[test]
    fn test_no_inverse_small() {
        let a = BigInteger::from(14u64);
        let m = BigInteger::from(49u64);

        let res = a.invert(&m);

        assert!(res.is_none());
    }

    #[test]
    fn test_modulo_assign() {
        let mut a = BigInteger::new(23, 64);
        let m = BigInteger::new(14, 64);

        a %= &m;
        assert_eq!(BigInteger::from(9u64), a);
    }

    #[test]
    fn test_modulo() {
        let a = BigInteger::new(23, 64);
        let m = BigInteger::new(14, 64);

        assert_eq!(BigInteger::from(9u64), a % &m);
    }
}

extern crate test;
use scicrypt_traits::randomness::{GeneralRng, SecureRng};
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
