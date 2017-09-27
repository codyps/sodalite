use super::*;
use rand::Rng;
extern crate test;

// This heavily uses GF math and is a good proxy for GF speed
#[bench]
fn bench_scalarmult(b: &mut test::Bencher) {
    let mut rng = ::rand::XorShiftRng::new_unseeded();
    b.iter(|| {
        let mut q: [u8;32] = unsafe { ::core::mem::uninitialized() };
        let mut n: [u8;32] = unsafe { ::core::mem::uninitialized() };
        let mut p: [u8;32] = unsafe { ::core::mem::uninitialized() };

        rng.fill_bytes(&mut n[..]);
        rng.fill_bytes(&mut p[..]);

        scalarmult(&mut q, &n, &p);
    });
}
