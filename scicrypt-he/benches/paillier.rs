#![allow(unused)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::OsRng;
use rug::Integer;
use scicrypt_he::cryptosystems::paillier::Paillier;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::Enrichable;

pub fn paillier_benchmark(c: &mut Criterion) {
    // Ignore noise up to 5%
    c.noise_threshold(0.05);

    let mut rng = GeneralRng::new(OsRng);
    let (public_key, secret_key) = Paillier::generate_keys(&BitsOfSecurity::AES128, &mut rng);

    // Benchmark encryption
    c.bench_function("paillier_encryption", |b| {
        b.iter(|| {
            Paillier::encrypt(
                &Integer::from(black_box(123456789u64)),
                &public_key,
                &mut rng,
            )
        })
    });

    // let ciphertext = Paillier::encrypt(&Integer::from(123456789u64), &public_key, &mut rng);

    // Benchmark decryption
    // c.bench_function("Paillier decryption", |b| b.iter(move || {
    //     let rich_ciphertext = ciphertext.enrich(&public_key);
    //     Paillier::decrypt(&rich_ciphertext, &secret_key);
    // }));
}

criterion_group!(paillier, paillier_benchmark);
criterion_main!(paillier);
