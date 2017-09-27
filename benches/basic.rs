#![no_std]
#![cfg_attr(feature = "bench", feature(test))]

extern crate rand;
extern crate test;
extern crate sodalite;

use rand::Rng;

// This heavily uses GF math and is a good proxy for GF speed
#[bench]
fn scalarmult(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut q: [u8;32] = unsafe { ::core::mem::uninitialized() };
        let mut n: [u8;32] = unsafe { ::core::mem::uninitialized() };
        let mut p: [u8;32] = unsafe { ::core::mem::uninitialized() };

        rng.fill_bytes(&mut n[..]);
        rng.fill_bytes(&mut p[..]);

        sodalite::scalarmult(&mut q, &n, &p);
    });
}

#[bench]
fn hash_rl(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut h: [u8;64] = unsafe { ::core::mem::uninitialized() };
        let mut m: [u8;1024] = unsafe { ::core::mem::uninitialized() };
        rng.fill_bytes(&mut m[..]);

        let len = rng.gen::<usize>() % m.len();

        sodalite::hash(&mut h, &m[..len]);
    });
}

#[bench]
fn hash_1k(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut h: [u8;64] = unsafe { ::core::mem::uninitialized() };
        let mut m: [u8;1024] = unsafe { ::core::mem::uninitialized() };
        rng.fill_bytes(&mut m[..]);
        sodalite::hash(&mut h, &m);
    });
}

#[bench]
fn hash_512(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut h: [u8;64] = unsafe { ::core::mem::uninitialized() };
        let mut m: [u8;512] = unsafe { ::core::mem::uninitialized() };
        rng.fill_bytes(&mut m[..]);
        sodalite::hash(&mut h, &m);
    });
}

