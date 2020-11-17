use criterion::{black_box, criterion_group, criterion_main, Criterion};
use index_fixed::index_fixed;
use rand::{Rng, RngCore, SeedableRng};
use rand_pcg::Pcg64 as BenchRng;

// This heavily uses GF math and is a good proxy for GF speed
fn scalarmult(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("scalarmult rand", |b| {
        b.iter(|| {
            let mut q: [u8; 32] = [0u8; 32];
            let mut n: [u8; 32] = [0u8; 32];
            let mut p: [u8; 32] = [0u8; 32];

            rng.fill_bytes(&mut n[..]);
            rng.fill_bytes(&mut p[..]);

            sodalite::scalarmult(&mut q, black_box(&n), black_box(&p));
        })
    });
}

fn hash_rl(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("hash_rl", |b| {
        b.iter(|| {
            let mut h: [u8; 64] = [0u8; 64];
            let mut m: [u8; 1024] = [0u8; 1024];
            rng.fill_bytes(&mut m[..]);

            let len = rng.gen::<usize>() % m.len();

            sodalite::hash(&mut h, black_box(&m[..len]));
        })
    });
}

fn hash_1k(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("hash_1k", |b| {
        b.iter(|| {
            let mut h: [u8; 64] = [0u8; 64];
            let mut m: [u8; 1024] = [0u8; 1024];
            rng.fill_bytes(&mut m[..]);
            sodalite::hash(&mut h, black_box(&m));
        })
    });
}

fn hash_512(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("hash_512", |b| {
        b.iter(|| {
            let mut h: [u8; 64] = [0u8; 64];
            let mut m: [u8; 512] = [0u8; 512];
            rng.fill_bytes(&mut m[..]);
            sodalite::hash(&mut h, black_box(&m));
        })
    });
}

fn secretbox_1k_rt(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("secretbox_1k_rt", |b| {
        b.iter(|| {
            let mut k: [u8; 32] = [0; 32];
            let mut m: [u8; 1024] = [0; 1024];
            let mut n: [u8; 24] = [0; 24];
            let mut mr = [0; 1024];
            let mut c = [0; 1024];

            *index_fixed!(&mut m; ..32) = [0u8; 32];
            rng.fill_bytes(&mut m[32..]);
            rng.fill_bytes(&mut k[..]);
            rng.fill_bytes(&mut n[..]);

            sodalite::secretbox(&mut c, &m, &n, &k).unwrap();
            sodalite::secretbox_open(&mut mr, &c, &n, &k).unwrap();
        })
    });
}

fn secretbox_1k(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("secretbox_1k", |b| {
        b.iter(|| {
            let mut k: [u8; 32] = [0; 32];
            let mut m: [u8; 1024] = [0; 1024];
            let mut n: [u8; 24] = [0; 24];
            let mut c = [0; 1024];

            *index_fixed!(&mut m; ..32) = [0u8; 32];
            rng.fill_bytes(&mut m[32..]);
            rng.fill_bytes(&mut k[..]);
            rng.fill_bytes(&mut n[..]);

            sodalite::secretbox(&mut c, &m, &n, &k).unwrap();
        })
    });
}

// verification is just another application of the same function + a verify, so we don't bench it
// seperately.
fn onetimeauth_1k(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("onetimeauth_1k", |b| {
        b.iter(|| {
            let mut k: [u8; 32] = [0; 32];
            let mut m: [u8; 1024] = [0; 1024];
            let mut a: [u8; 16] = [0; 16];

            rng.fill_bytes(&mut m[..]);
            rng.fill_bytes(&mut k[..]);

            sodalite::onetimeauth(&mut a, &m, &k)
        })
    });
}

fn box_1k_rt(c: &mut Criterion) {
    let mut rng = BenchRng::from_rng(rand::thread_rng()).unwrap();
    c.bench_function("box_1k_rt", |b| {
        b.iter(|| {
            let mut s_pk: sodalite::BoxPublicKey = [0; 32];
            let mut s_sk: sodalite::BoxSecretKey = [0; 32];
            let mut r_pk: sodalite::BoxPublicKey = [0; 32];
            let mut r_sk: sodalite::BoxSecretKey = [0; 32];
            let mut seed: [u8; 32] = [0; 32];

            rng.fill_bytes(&mut seed[..]);
            sodalite::box_keypair_seed(&mut r_pk, &mut r_sk, &seed);

            rng.fill_bytes(&mut seed[..]);
            sodalite::box_keypair_seed(&mut s_pk, &mut s_sk, &seed);

            let mut m: [u8; 1024] = [0; 1024];
            let mut n: [u8; 24] = [0; 24];

            *index_fixed!(&mut m; ..32) = [0u8; 32];
            rng.fill_bytes(&mut m[32..]);
            rng.fill_bytes(&mut n[..]);

            let mut c = [0; 1024];
            let mut mr = [0; 1024];

            sodalite::box_(&mut c, &m, &n, &r_pk, &s_sk).unwrap();

            sodalite::box_open(&mut mr, &c, &n, &s_pk, &r_sk).unwrap();
        })
    });
}

criterion_group!(
    benches,
    scalarmult,
    hash_rl,
    hash_1k,
    hash_512,
    secretbox_1k,
    secretbox_1k_rt,
    onetimeauth_1k,
    box_1k_rt
);
criterion_main!(benches);
