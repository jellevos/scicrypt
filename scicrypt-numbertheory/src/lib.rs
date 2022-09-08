#![warn(missing_docs, unused_imports)]

//! _This is a part of **scicrypt**. For more information, head to the
//! [scicrypt](https://crates.io/crates/scicrypt) crate homepage._
//!
//! Number theoretic functions, particularly suited for cryptography. Functions include extremely
//! fast (safe) prime generation.

mod primes;

use crate::primes::FIRST_PRIMES;
use scicrypt_bigint::UnsignedInteger;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::randomness::SecureRng;

/// Generates a uniformly random prime number of a given bit length. So, the number contains
/// `bit_length` bits, of which the first and the last bit are always 1.
pub fn gen_prime<R: SecureRng>(bit_length: u32, rng: &mut GeneralRng<R>) -> UnsignedInteger {
    'outer: loop {
        let mut candidate = UnsignedInteger::random(bit_length, rng);
        candidate.set_bit(bit_length - 1);
        candidate.set_bit(0);

        // A heuristic that closely follows OpenSSL (https://github.com/openssl/openssl/blob/4cedf30e995f9789cf6bb103e248d33285a84067/crypto/bn/bn_prime.c)
        let prime_count: usize = bit_length as usize / 3;
        let mods: Vec<u64> = FIRST_PRIMES[..prime_count]
            .iter()
            .map(|p| candidate.mod_u(*p))
            .collect();

        let mut delta = 0;
        let max_delta = u64::MAX - FIRST_PRIMES.last().unwrap();
        candidate += &'sieve: loop {
            for i in 1..prime_count {
                if (mods[i] + delta) % FIRST_PRIMES[i] == 0 {
                    // For candidate x and prime p, if x % p = 0 then x is not prime
                    // So, we go to the next odd number and try again
                    delta += 2;

                    if delta > max_delta {
                        continue 'outer;
                    }

                    continue 'sieve;
                }
            }

            // If we have passed all prime_count first primes, then we are fairly certain this is a prime!
            break UnsignedInteger::from(delta);
        };

        // Ensure that we have a prime with a stronger primality test
        if candidate.is_probably_prime() {
            return candidate;
        }
    }
}

/// Generates a uniformly random *safe* prime number of a given bit length. This is a prime $p$ of
/// the form $p = 2q + 1$, where $q$ is a smaller prime.
pub fn gen_safe_prime<R: SecureRng>(bit_length: u32, rng: &mut GeneralRng<R>) -> UnsignedInteger {
    'outer: loop {
        let mut candidate = UnsignedInteger::random(bit_length, rng);
        candidate.set_bit(bit_length - 1);
        candidate.set_bit(0);

        // A heuristic that closely follows OpenSSL (https://github.com/openssl/openssl/blob/4cedf30e995f9789cf6bb103e248d33285a84067/crypto/bn/bn_prime.c)
        let prime_count: usize = bit_length as usize / 3;
        let mods: Vec<u64> = FIRST_PRIMES[..prime_count]
            .iter()
            .map(|p| candidate.mod_u(*p))
            .collect();

        let mut delta = 0;
        let max_delta = u64::MAX - FIRST_PRIMES[prime_count - 1];
        candidate += &'sieve: loop {
            for i in 1..prime_count {
                if (mods[i] + delta) % FIRST_PRIMES[i] <= 1 {
                    // For candidate x and prime p, if x % p = 0 then x is not prime
                    // So, we go to the next odd number and try again
                    delta += 4;

                    if delta > max_delta {
                        continue 'outer;
                    }

                    continue 'sieve;
                }
            }

            // If we have passed all prime_count first primes, then we are fairly certain this is a prime!
            break UnsignedInteger::from(delta);
        };

        // Ensure that we have a prime with a stronger primality test
        if candidate.is_probably_prime() {
            // Ensure that p for 2p = 1 is also a prime with the stronger primality test
            let candidate_reduced = &candidate >> 1;
            if candidate_reduced.is_probably_prime() {
                return candidate;
            }
        }
    }
}

/// Generates a uniformly random RSA modulus, which is the product of two safe primes $p$ and $q$.
/// This method returns both the modulus and $\lambda$, which is the least common multiple of
/// $p - 1$ and $q - 1$.
pub fn gen_rsa_modulus<R: SecureRng>(
    bit_length: u32,
    rng: &mut GeneralRng<R>,
) -> (UnsignedInteger, UnsignedInteger) {
    let mut p = gen_safe_prime(bit_length / 2, rng);
    let mut q = gen_safe_prime(bit_length / 2, rng);

    let n = &p * &q;

    p.clear_bit(0);
    q.clear_bit(0);

    let lambda = p.lcm(&q);

    (n, lambda)
}

#[cfg(test)]
mod tests {
    use crate::{gen_prime, gen_safe_prime};
    use rand_core::OsRng;
    use scicrypt_bigint::UnsignedInteger;
    use scicrypt_traits::randomness::GeneralRng;

    fn assert_primality_100_000_factors(integer: &UnsignedInteger) {
        let (_, hi) = primal::estimate_nth_prime(100_000);
        for prime in primal::Sieve::new(hi as usize).primes_from(0) {
            assert!(
                integer.mod_u(prime as u64) != 0,
                "{} is divisible by {}",
                integer,
                prime
            );
        }
    }

    #[test]
    fn test_gen_prime_for_factors() {
        let mut rng = GeneralRng::new(OsRng);
        let generated_prime = gen_prime(256, &mut rng);

        assert_primality_100_000_factors(&generated_prime);
    }

    #[test]
    fn test_gen_safe_prime_for_factors() {
        let mut rng = GeneralRng::new(OsRng);
        let generated_prime = gen_safe_prime(256, &mut rng);

        assert_primality_100_000_factors(&generated_prime);

        let sophie_germain_prime = &generated_prime >> 1;

        assert_primality_100_000_factors(&sophie_germain_prime);
    }
}
