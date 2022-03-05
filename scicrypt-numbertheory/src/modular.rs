trait EvenOdd {
    fn is_even(&self) -> bool;
    fn is_odd(&self) -> bool;
}

impl EvenOdd for usize {
    fn is_even(&self) -> bool {
        (self & 1) == 0
    }

    fn is_odd(&self) -> bool {
        (self & 1) == 1
    }
}

impl EvenOdd for isize {
    fn is_even(&self) -> bool {
        (self & 1) == 0
    }

    fn is_odd(&self) -> bool {
        (self & 1) == 1
    }
}

// Montgomery multiplication algorithm (Handbook of Applied Cryptography 14.36)
pub fn mod_mul_montgomery(x: usize, y: usize, m: usize) -> usize {
    let mut a = 0;
    for i in 0..(usize::BITS - 1) {
        let u = ((a & 1) + ((x >> i) & 1) * (y & 1)) & 1;
        a = (a + ((x >> i) & 1) * y + u * m) >> 1;
    }

    if a >= m {
        a -= m;
    }

    a // is xyR^-1 mod m
}

pub fn mod_mul(x: usize, y: usize, m: usize) -> usize {
    // Compute xyR^-1 mod m and R^2 mod m, and multiply the two again
    let xy = mod_mul_montgomery(x, y, m);
    let r_mod_m = (usize::MAX - m + 1) % m;
    let r2_mod_m = (r_mod_m * r_mod_m) % m;
    mod_mul_montgomery(xy, r2_mod_m, m)
}

// Binary Greatest Common Divisor algorithm (Handbook of Applied Cryptography 14.54)
pub fn gcd(mut x: usize, mut y: usize) -> usize {
    let mut g = 1;
    while x.is_even() && y.is_even() {
        x >>= 1;
        y >>= 1;
        g <<= 1;
    }

    while x != 0 {
        while x.is_even() {
            x >>= 1;
        }

        while y.is_even() {
            y >>= 1;
        }

        if x >= y {
            x -= y;
            x >>= 1;
        } else {
            y -= x;
            y >>= 1;
        }
    }

    g * y
}

// Binary extended Greatest Common Divisor algorithm (Handbook of Applied Cryptography 14.61)
pub fn extended_gcd(mut x: isize, mut y: isize) -> (isize, (isize, isize)) {
    let mut g = 1;
    while x.is_even() && y.is_even() {
        x >>= 1;
        y >>= 1;
        g <<= 1;
    }

    let mut u: isize = x;
    let mut v: isize = y;

    let mut a: isize = 1;
    let mut b: isize = 0;
    let mut c: isize = 0;
    let mut d: isize = 1;

    while u != 0 {
        while u.is_even() {
            u >>= 1;

            if a.is_even() && b.is_even() {
                a >>= 1;
                b >>= 1;
                continue
            }

            a += y;
            a >>= 1;
            b -= x;
            b >>= 1;
        }

        while v.is_even() {
            v >>= 1;

            if c.is_even() && d.is_even() {
                c >>= 1;
                d >>= 1;
                continue
            }

            c += y;
            c >>= 1;
            d -= x;
            d >>= 1;
        }

        if u >= v {
            u -= v;
            a -= c;
            b -= d;
        } else {
            v -= u;
            c -= a;
            d -= b;
        }
    }

    (g * v, (c, d))
}

// TODO: We can potentially implement a gcd and mult_inv method specifically for a^-1 mod m when m is odd, see note 14.64
pub fn mult_inv(a: usize, m: usize) -> usize {
    let (v, (c, d)) = extended_gcd(a as isize, m as isize);
    if v != 1 {
        panic!("a is not invertible wrt m");
    }

    if d >= 0 {
        d as usize
    } else {
        (m as isize + d) as usize
    }
}

// Garner's algorithm for the Chinese Remainder Theorem (Handbook of Applied Cryptography 14.71)
// pub fn crt(reduced_values: Vec<usize>, moduli: Vec<usize>) -> usize {
//     assert_eq!(reduced_values.len(), moduli.len());
//     let t = moduli.len();
//     for i in 2..t {
//         let mut c = 1;
//
//         for j in 1..(i - 1) {
//             let u = moduli[j]
//         }
//     }
//
//     0
// }

#[cfg(test)]
mod tests {
    use rand::Rng;
    use rand_core::OsRng;
    use crate::modular::{EvenOdd, extended_gcd, gcd, mod_mul, mult_inv};

    #[test]
    fn test_isize_even() {
        for _ in 0..1000 {
            let x: isize = OsRng.gen_range(0..1_000_000_000) * 2;
            assert!(x.is_even());
        }
    }

    #[test]
    fn test_isize_odd() {
        for _ in 0..1000 {
            let x: isize = OsRng.gen_range(0..1_000_000_000) * 2 + 1;
            assert!(x.is_odd());
        }
    }

    #[test]
    fn test_usize_even() {
        for _ in 0..1000 {
            let x: usize = OsRng.gen_range(0..1_000_000_000) * 2;
            assert!(x.is_even());
        }
    }

    #[test]
    fn test_usize_odd() {
        for _ in 0..1000 {
            let x: usize = OsRng.gen_range(0..1_000_000_000) * 2 + 1;
            assert!(x.is_odd());
        }
    }

    #[test]
    fn gcd_primes() {
        let x = 683;
        let y = 983;
        assert_eq!(gcd(x, y), 1, "The GCD of primes {} and {} must be 1", x, y)
    }

    #[test]
    fn gcd_2exp() {
        let x = 2usize.pow(13);
        let y = 2usize.pow(17);
        assert_eq!(gcd(x, y), x, "The GCD of 2^13 and 2^17 must be 2^13")
    }

    #[test]
    fn test_gcd_equals_extended() {
        // Test for 100_000 random values whether the gcd and extended gcd agree
        for _ in 0..100_000 {
            let x: usize = OsRng.gen_range(0..1_000_000_000);
            let y: usize = OsRng.gen_range(0..1_000_000_000);

            let gcd_res = gcd(x, y);
            let (extended_gcd_res, _) = extended_gcd(x as isize, y as isize);

            assert_eq!(gcd_res, extended_gcd_res as usize, "GCD and extended GCD did not agree: {} == GCD({}, {}) == {}", gcd_res, x, y, extended_gcd_res);
        }
    }

    #[test]
    fn gcd_extended_2exp() {
        let x = 2isize.pow(13);
        let y = 2isize.pow(17);
        let (v, (a, b)) = extended_gcd(x, y);
        println!("{}: {} {} + {} {}", v, a, x, b, y);
        assert_eq!(v, x);
        assert_eq!(a, 1);
        assert_eq!(b, 0);
    }

    #[test]
    fn gcd_extended_small() {
        let x = 693;
        let y = 609;
        let (v, (a, b)) = extended_gcd(x, y);
        println!("{}: {} {} + {} {}", v, a, x, b, y);
        assert_eq!(v, 21);
        assert_eq!(a, -181);
        assert_eq!(b, 206);
    }

    #[test]
    fn test_gcd_extended_random() {
        // Test for 100_000 random values whether the gcd and extended gcd agree
        for _ in 0..10_000 {
            let x: isize = OsRng.gen_range(0..1_000_000_000);
            let y: isize = OsRng.gen_range(0..1_000_000_000);

            let (v, (a, b)) = extended_gcd(x, y);

            println!("{}: {} {} + {} {}", v, a, x, b, y);
            assert_eq!(v, a * x + b * y);
        }
    }

    #[test]
    fn gcd_mult_inv_random() {
        for _ in 0..10_000 {
            let m: usize = 8333534987;  // Prime number
            let a: usize = OsRng.gen_range(0..m);

            assert_eq!(a * mult_inv(a, m) % m, 1);
        }
    }

    #[test]
    fn gcd_mod_mul_random() {
        for _ in 0..10_000 {
            let m: usize = 8333534987;  // Prime number
            let a: usize = OsRng.gen_range(0..(m / 2));
            let b: usize = OsRng.gen_range(0..(m / 2));

            assert_eq!(mod_mul(a, b, m), (a * b) % m);
        }
    }
}
