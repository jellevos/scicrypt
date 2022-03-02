

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


#[cfg(test)]
mod tests {
    use rand::Rng;
    use rand_core::OsRng;
    use crate::modular::{EvenOdd, extended_gcd, gcd};

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
}
