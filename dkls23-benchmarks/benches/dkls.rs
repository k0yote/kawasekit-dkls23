//! Criterion timing benches: dkg / sign / refresh_complete / refresh_fast,
//! each on secp256k1 and secp256r1, at 2-of-2. Timings are compute-only
//! (NoMeter — no serialization in the hot path). Sign/refresh use iter_batched
//! so DKG setup is excluded from the measured time.
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use dkls23_benchmarks::meter::NoMeter;
use dkls23_benchmarks::{run_dkg, run_refresh_complete, run_refresh_fast, run_sign};
use dkls23_core::protocols::Parameters;
use dkls23_core::utilities::hashes::tagged_hash;

const SESSION_ID: [u8; 32] = [7u8; 32];
const REFRESH_SID: [u8; 32] = [5u8; 32];
const SIGN_ID: [u8; 32] = [9u8; 32];

fn params() -> Parameters {
    Parameters::new(2, 2).unwrap()
}

fn bench_dkg(c: &mut Criterion) {
    let p = params();
    let mut g = c.benchmark_group("dkg");
    g.bench_function("secp256k1", |b| {
        b.iter(|| black_box(run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter)))
    });
    g.bench_function("secp256r1", |b| {
        b.iter(|| black_box(run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter)))
    });
    g.finish();
}

fn bench_sign(c: &mut Criterion) {
    let p = params();
    let msg = tagged_hash(b"bench", &[b"m"]);
    let mut g = c.benchmark_group("sign");
    g.bench_function("secp256k1", |b| {
        b.iter_batched(
            || run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter),
            |parties| {
                black_box(run_sign::<k256::Secp256k1, _>(
                    &parties,
                    2,
                    &SIGN_ID,
                    msg,
                    &mut NoMeter,
                ))
            },
            BatchSize::SmallInput,
        )
    });
    g.bench_function("secp256r1", |b| {
        b.iter_batched(
            || run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter),
            |parties| {
                black_box(run_sign::<p256::NistP256, _>(
                    &parties,
                    2,
                    &SIGN_ID,
                    msg,
                    &mut NoMeter,
                ))
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_refresh_complete(c: &mut Criterion) {
    let p = params();
    let mut g = c.benchmark_group("refresh_complete");
    g.bench_function("secp256k1", |b| {
        b.iter_batched(
            || run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_complete::<k256::Secp256k1, _>(
                    &mut parties,
                    &REFRESH_SID,
                    &mut NoMeter,
                ))
            },
            BatchSize::SmallInput,
        )
    });
    g.bench_function("secp256r1", |b| {
        b.iter_batched(
            || run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_complete::<p256::NistP256, _>(
                    &mut parties,
                    &REFRESH_SID,
                    &mut NoMeter,
                ))
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_refresh_fast(c: &mut Criterion) {
    let p = params();
    let mut g = c.benchmark_group("refresh_fast");
    g.bench_function("secp256k1", |b| {
        b.iter_batched(
            || run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_fast::<k256::Secp256k1, _>(
                    &mut parties,
                    &REFRESH_SID,
                    &mut NoMeter,
                ))
            },
            BatchSize::SmallInput,
        )
    });
    g.bench_function("secp256r1", |b| {
        b.iter_batched(
            || run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_fast::<p256::NistP256, _>(
                    &mut parties,
                    &REFRESH_SID,
                    &mut NoMeter,
                ))
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_dkg,
    bench_sign,
    bench_refresh_complete,
    bench_refresh_fast
);
criterion_main!(benches);
