use crate::randomness::SecureRng;
use rug::integer::IsPrime;
use rug::Integer;

const REPS: u32 = 25;

pub fn gen_prime<R: rand_core::RngCore + rand_core::CryptoRng>(
    bit_length: u32,
    rng: &mut SecureRng<R>,
) -> Integer {
    loop {
        let mut candidate = Integer::from(Integer::random_bits(bit_length, &mut rng.rug_rng()));

        let set_bits = (Integer::from(1) << (bit_length - 1)) + Integer::from(1);
        candidate |= set_bits;

        if candidate.is_probably_prime(REPS) != IsPrime::No {
            return candidate;
        }
    }
}

pub fn gen_safe_prime<R: rand_core::RngCore + rand_core::CryptoRng>(
    bit_length: u32,
    rng: &mut SecureRng<R>,
) -> Integer {
    loop {
        let mut candidate = gen_prime(bit_length - 1, rng);

        candidate <<= 1;
        candidate |= Integer::from(1);

        if !candidate.mod_u(3) == 2 {
            continue;
        }

        if candidate.is_probably_prime(REPS) != IsPrime::No {
            return candidate;
        }
    }
}

pub fn gen_rsa_modulus<R: rand_core::RngCore + rand_core::CryptoRng>(
    bit_length: u32,
    rng: &mut SecureRng<R>,
) -> (Integer, Integer) {
    let p = gen_safe_prime(bit_length / 2, rng);
    let q = gen_safe_prime(bit_length / 2, rng);

    let n = Integer::from(&p * &q);

    let lambda: Integer = (p - Integer::from(1)).lcm(&(q - Integer::from(1)));

    (n, lambda)
}

pub fn gen_coprime<R: rand_core::RngCore + rand_core::CryptoRng>(
    other: &Integer,
    rng: &mut SecureRng<R>,
) -> Integer {
    loop {
        let candidate = Integer::from(other.random_below_ref(&mut rng.rug_rng()));

        if Integer::from(candidate.gcd_ref(other)) == 1 {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::number_theory::{gen_prime, gen_safe_prime};
    use crate::randomness::SecureRng;
    use rand_core::OsRng;
    use rug::Integer;

    fn assert_primality_100_000_factors(integer: &Integer) {
        let (_, hi) = primal::estimate_nth_prime(100_000);
        for prime in primal::Sieve::new(hi as usize).primes_from(0) {
            assert!(
                !integer.is_divisible_u(prime as u32),
                "{} is divisible by {}",
                integer,
                prime
            );
        }
    }

    #[test]
    fn test_gen_prime_for_factors() {
        let mut rng = SecureRng::new(OsRng);
        let generated_prime = gen_prime(256, &mut rng);

        assert_primality_100_000_factors(&generated_prime);
    }

    #[test]
    fn test_gen_safe_prime_for_factors() {
        let mut rng = SecureRng::new(OsRng);
        let generated_prime = gen_safe_prime(256, &mut rng);

        assert_primality_100_000_factors(&generated_prime);

        let sophie_germain_prime = generated_prime >> 1;

        assert_primality_100_000_factors(&sophie_germain_prime);
    }
}
