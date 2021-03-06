#![allow(unused)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use glass_pumpkin::safe_prime::from_rng;
use openssl::bn::BigNum;
use rand::rngs;
use rand_core::OsRng;
use scicrypt_numbertheory::gen_safe_prime;
use scicrypt_traits::randomness::GeneralRng;

pub fn safe_prime_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("safe_prime_benchmark");
    group.sample_size(50);

    for bit_length in [128usize, 192usize, 256usize, 320usize, 384usize].iter() {
        //group.throughput(Throughput::Bytes(*bit_length as u64));

        // Benchmark our `gen_safe_prime` function
        let mut rng = GeneralRng::new(OsRng);
        group.bench_with_input(
            BenchmarkId::new("gen_safe_prime", bit_length),
            bit_length,
            |b, &bits| {
                b.iter(|| gen_safe_prime(black_box(bits as u32), &mut rng));
            },
        );

        // Benchmark `glass_pumpkin`'s safe prime generation
        let mut rng = rand::rngs::OsRng;
        group.bench_with_input(
            BenchmarkId::new("glass_pumpkin", bit_length),
            bit_length,
            |b, &bits| {
                b.iter(|| from_rng(black_box(bits), &mut rng));
            },
        );

        // Benchmark `openssl`'s safe prime generation
        let mut rng = rand::rngs::OsRng;
        group.bench_with_input(
            BenchmarkId::new("openssl", bit_length),
            bit_length,
            |b, &bits| {
                b.iter(|| {
                    let mut big = BigNum::new().unwrap();
                    big.generate_prime(bits as i32, true, None, None);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(safe_primes, safe_prime_benchmark);
criterion_main!(safe_primes);
