#![cfg(test)]

extern crate core;
extern crate rand;
extern crate tweetnacl;

use self::rand::Rng;
use self::rand::RngCore;

fn prob_test<T: FnMut()>(ct: u64, mut t: T) {
    for _ in 0..ct {
        t();
    }
}

#[test]
fn hashblock() {
    let mut rng = rand::thread_rng();
    prob_test(10, || {
        // 1 KiB, arbitrary
        let len = rng.gen_range(core::usize::MIN, 1024);
        let mut back = [0u8;1024];
        let b = &mut back[0..len];
        rng.fill_bytes(b);

        let mut hash1 = [0u8;64];
        let v1 = super::hashblocks(&mut hash1, b);

        let mut hash2 = [0u8;64];
        let v2 = tweetnacl::hashblocks_sha512(&mut hash2, b);

        assert_eq!(&hash1[..], &hash2[..]);
        assert_eq!(v1, v2);
    })
}


#[test]
fn mod_l() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        let mut r = [0u8;32];
        let mut x = [0i64;64];

        rng.fill_bytes(&mut r[..]);
        for v in x.iter_mut() {
            *v = rng.gen::<u16>() as i64;
        }

        let mut r2 = r;
        let mut x2 = x;

        super::mod_l(&mut r, &mut x);
        tweetnacl::mod_l(&mut r2, &mut x2);

        assert_eq!(&r[..], &r2[..]);
        assert_eq!(&x[..], &x2[..])
    })

}

#[test]
fn core_salsa20() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        let mut inx = [0u8;16];
        rng.fill_bytes(&mut inx);

        let mut k = [0u8;32];
        rng.fill_bytes(&mut k);

        let mut c = [0u8;16];
        rng.fill_bytes(&mut c);

        let mut out1 = [0u8;64];
        super::core_salsa20(&mut out1, &inx, &k, &c);
        let mut out2 = [0u8;64];
        tweetnacl::core_salsa20(&mut out2, &inx, &k, &c);
        assert_eq!(&out1[..], &out2[..]);
    })
}

#[test]
fn core_hsalsa20() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        let mut inx = [0u8;16];
        rng.fill_bytes(&mut inx);

        let mut k = [0u8;32];
        rng.fill_bytes(&mut k);

        let mut c = [0u8;16];
        rng.fill_bytes(&mut c);

        let mut out1 = [0u8;32];
        super::core_hsalsa20(&mut out1, &inx, &k, &c);
        let mut out2 = [0u8;32];
        tweetnacl::core_hsalsa20(&mut out2, &inx, &k, &c);
        assert_eq!(&out1[..], &out2[..]);
    })
}

#[test]
fn stream_salsa20_xor() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        let mut inx = [0u8;16];
        rng.fill_bytes(&mut inx);

        let mut n = [0u8;8];
        rng.fill_bytes(&mut n);

        let mut c = [0u8;32];
        rng.fill_bytes(&mut c);

        // 1024 is arbitrary
        let b = rng.gen_range(0, 1024);
        let mut out1_b = [0u8;1024];
        let mut out2_b = [0u8;1024];

        let out1 = &mut out1_b[0..b];
        super::stream_salsa20_xor(out1, None, &n, &c);
        let out2 = &mut out2_b[0..b];
        tweetnacl::stream_salsa20_xor(out2, None, &n, &c);
        assert_eq!(&out1[..], &out2[..]);
    })
}

#[test]
fn scalarmult() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        let mut p = [0u8;32];
        rng.fill_bytes(&mut p);

        let mut q1 = [0u8;32];
        super::scalarmult_base(&mut q1, &p);
        let mut q2 = [0u8;32];
        tweetnacl::scalarmult_base(&mut q2, &p);
        assert_eq!(&q1[..], &q2[..]);
    })
}

