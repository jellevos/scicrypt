use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::OsRng;
use scicrypt_bigint::UnsignedInteger;
use scicrypt_he::cryptosystems::curve_el_gamal::{CurveElGamal, PrecomputedCurveElGamalPK};
use scicrypt_he::cryptosystems::integer_el_gamal::{IntegerElGamal, IntegerElGamalPK};
use scicrypt_he::cryptosystems::paillier::{Paillier, PaillierPK};
use scicrypt_he::cryptosystems::rsa::{Rsa, RsaPK};
use scicrypt_traits::cryptosystems::{AsymmetricCryptosystem, DecryptionKey, EncryptionKey};
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::security::BitsOfSecurity;

fn cryptosystem_benchmark<PK: EncryptionKey, CS: AsymmetricCryptosystem<PublicKey = PK>>(
    name: &str,
    c: &mut Criterion,
    plaintext: PK::Plaintext,
) {
    // Ignore noise up to 5%
    let mut group = c.benchmark_group(name);
    group.noise_threshold(0.05);

    let mut rng = GeneralRng::new(OsRng);
    let cryptosystem = CS::setup(&BitsOfSecurity::AES128);
    let (public_key, secret_key) = cryptosystem.generate_keys(&mut rng);

    // Benchmark encryption
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            black_box(public_key.encrypt(&plaintext, &mut rng));
        })
    });

    let ciphertext = public_key.encrypt(&plaintext, &mut rng);

    // Benchmark decryption
    group.bench_function("decrypt", |b| {
        b.iter(|| black_box(secret_key.decrypt(&ciphertext)))
    });
}

fn paillier_benchmark(c: &mut Criterion) {
    cryptosystem_benchmark::<PaillierPK, Paillier>(
        "paillier",
        c,
        UnsignedInteger::from(123456789u64),
    );
}

fn rsa_benchmark(c: &mut Criterion) {
    cryptosystem_benchmark::<RsaPK, Rsa>("rsa", c, UnsignedInteger::from(123456789u64));
}

fn curve_elgamal_benchmark(c: &mut Criterion) {
    cryptosystem_benchmark::<PrecomputedCurveElGamalPK, CurveElGamal>(
        "curve_elgamal",
        c,
        RISTRETTO_BASEPOINT_POINT,
    );
}

fn integer_elgamal_benchmark(c: &mut Criterion) {
    cryptosystem_benchmark::<IntegerElGamalPK, IntegerElGamal>(
        "integer_elgamal",
        c,
        UnsignedInteger::from(123456789u64),
    );
}

criterion_group!(
    benches,
    paillier_benchmark,
    rsa_benchmark,
    curve_elgamal_benchmark,
    integer_elgamal_benchmark
);
criterion_main!(benches);
