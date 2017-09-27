#![no_std]
#![cfg_attr(feature = "bench", feature(test))]

extern crate rand;
extern crate test;
extern crate sodalite;
#[macro_use]
extern crate index_fixed;

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

#[bench]
fn secretbox_1k_rt(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut k: [u8;32] = unsafe { ::core::mem::uninitialized() };
        let mut m: [u8;1024] = unsafe { ::core::mem::uninitialized() };
        let mut n: [u8;24] = unsafe { ::core::mem::uninitialized() };
        let mut mr = [0;1024];
        let mut c = [0;1024];

        *index_fixed!(&mut m; ..32) = [0u8;32];
        rng.fill_bytes(&mut m[32..]);
        rng.fill_bytes(&mut k[..]);
        rng.fill_bytes(&mut n[..]);


        sodalite::secretbox(&mut c, &m, &n, &k).unwrap();
        sodalite::secretbox_open(&mut mr, &c, &n, &k).unwrap();
    });
}

#[bench]
fn secretbox_1k(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut k: [u8;32] = unsafe { ::core::mem::uninitialized() };
        let mut m: [u8;1024] = unsafe { ::core::mem::uninitialized() };
        let mut n: [u8;24] = unsafe { ::core::mem::uninitialized() };
        let mut c = [0;1024];

        *index_fixed!(&mut m; ..32) = [0u8;32];
        rng.fill_bytes(&mut m[32..]);
        rng.fill_bytes(&mut k[..]);
        rng.fill_bytes(&mut n[..]);


        sodalite::secretbox(&mut c, &m, &n, &k).unwrap();
    });
}

// verification is just another application of the same function + a verify, so we don't bench it
// seperately.
#[bench]
fn onetimeauth_1k(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut k: [u8;32] = unsafe { ::core::mem::uninitialized() };
        let mut m: [u8;1024] = unsafe { ::core::mem::uninitialized() };
        let mut a: [u8;16] = unsafe { ::core::mem::uninitialized() };

        rng.fill_bytes(&mut m[..]);
        rng.fill_bytes(&mut k[..]);

        sodalite::onetimeauth(&mut a, &m, &k)
    });
}


