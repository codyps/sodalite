/*
 * TODO: add test vectors
 */

extern crate tweetnacl;
extern crate sodalite;
extern crate rand;

use self::rand::Rng;
use self::rand::RngCore;

fn prob_test<T: FnMut()>(ct: u64, mut t: T) {
    for _ in 0..ct {
        t();
    }
}

#[test]
fn hash() {
    let mut rng = rand::thread_rng();
    prob_test(10, || {
        // 1 KiB, arbitrary
        let len = rng.gen_range(std::usize::MIN, 1024);
        //let len = 127;

        println!("length: {}", len);

        let mut b = vec![0u8;len];
        rng.fill_bytes(&mut b);

        let mut hash1 = [0u8;64];
        sodalite::hash(&mut hash1, &b);
        let mut hash2 = [0u8;64];
        tweetnacl::hash_sha512(&mut hash2, &b);

        assert_eq!(&hash1[..], &hash2[..]);
    })
}

#[test]
fn onetimeauth() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        let len = rng.gen_range(std::usize::MIN, 1024);
        println!("length: {}", len);

        let mut m = vec![0u8;len];
        rng.fill_bytes(&mut m);

        let mut k = [0u8;32];
        rng.fill_bytes(&mut k);

        let mut out1 = [0u8;16];
        sodalite::onetimeauth(&mut out1, &m, &k);
        let mut out2 = [0u8;16];
        tweetnacl::onetimeauth(&mut out2, &m, &k);
        assert_eq!(&out1[..], &out2[..]);

        let r1 = sodalite::onetimeauth_verify(&out1, &m, &k);
        let r2 = tweetnacl::onetimeauth_verify(&out2, &m, &k);
        assert_eq!(r1, r2);
    })
}

#[test]
fn stream() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        let len = rng.gen_range(0, 1024);
        println!("length: {}", len);

        let mut m = vec![0u8;len];
        rng.fill_bytes(&mut m);

        let mut n = [0u8;24];
        rng.fill_bytes(&mut n);

        let mut k = [0u8;32];
        rng.fill_bytes(&mut k);

        let mut out1 = vec![0u8;len];
        sodalite::stream_xsalsa20(&mut out1, &n, &k);
        let mut out2 = vec![0u8;len];
        tweetnacl::stream(&mut out2, &n, &k);
        assert_eq!(&out1[..], &out2[..]);

        let mut out1 = vec![0u8;len];
        sodalite::stream_xsalsa20_xor(&mut out1, &m, &n, &k);
        let mut out2 = vec![0u8;len];
        tweetnacl::stream_xor(&mut out2, &m, &n, &k);
        assert_eq!(&out1[..], &out2[..]);
    })
}

#[test]
fn box_() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        // max length is arbitrary, 32 is minimum size of crypo_box and must be zeroed.
        let len = rng.gen_range(32, 1024);
        println!("length: {}", len);

        let mut m = vec![0u8;len];
        rng.fill_bytes(&mut m[32..]);

        let mut n = [0u8;24];
        rng.fill_bytes(&mut n);

        let mut pk = [0u8;32];
        let mut sk = [0u8;32];

        let mut seed = [0u8;32];
        rng.fill_bytes(&mut seed);
        sodalite::box_keypair_seed(&mut pk, &mut sk, &seed);

        let mut out1 = vec![0u8;len];
        sodalite::box_(&mut out1, &m, &n, &pk, &sk).unwrap();
        let mut out2 = vec![0u8;len];
        tweetnacl::box_(&mut out2, &m, &n, &pk, &sk).unwrap();
        assert_eq!(&out1[..], &out2[..]);

        let mut dec1 = vec![0u8;len];
        sodalite::box_open(&mut dec1, &out1, &n, &pk, &sk).unwrap();
        let mut dec2 = vec![0u8;len];
        tweetnacl::box_open(&mut dec2, &out2, &n, &pk, &sk).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, m);


        /* TODO: "corrupt" some data and ensure it doesn't open the box */
    })
}

#[test]
fn secretbox() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        // upper bound is arbitrary, 32 is required minimum length by secretbox, but doesn't trigger
        // any encryption (need +1 for that).
        let len = rng.gen_range(33, 1024);
        println!("length: {}", len);

        let mut m = vec![0u8;len];
        rng.fill_bytes(&mut m[32..]);

        let mut n = [0u8;24];
        rng.fill_bytes(&mut n);

        let mut k = [0u8;32];
        rng.fill_bytes(&mut k);

        let mut out1 = vec![0u8;len];
        sodalite::secretbox(&mut out1, &m, &n, &k).unwrap();
        let mut out2 = vec![0u8;len];
        tweetnacl::secretbox(&mut out2, &m, &n, &k).unwrap();
        assert_eq!(&out1[..], &out2[..]);

        let mut dec1 = vec![0u8;len];
        sodalite::secretbox_open(&mut dec1, &out1, &n, &k).unwrap();
        let mut dec2 = vec![0u8;len];
        tweetnacl::secretbox_open(&mut dec2, &out2, &n, &k).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, m);


        /* TODO: "corrupt" some data and ensure it doesn't open the box */
    })
}

#[test]
fn sign() {
    let mut rng = rand::thread_rng();

    prob_test(10, || {
        // max length is arbitrary
        let len = rng.gen_range(0, 1024);
        println!("length: {}", len);

        let mut m = vec![0u8;len];
        rng.fill_bytes(&mut m);

        let mut pk = [0u8;sodalite::SIGN_PUBLIC_KEY_LEN];
        let mut sk = [0u8;sodalite::SIGN_SECRET_KEY_LEN];
        let mut pk2 = [0u8;sodalite::SIGN_PUBLIC_KEY_LEN];
        let mut sk2 = [0u8;sodalite::SIGN_SECRET_KEY_LEN];

        let mut seed = [0u8;sodalite::SIGN_PUBLIC_KEY_LEN];
        rng.fill_bytes(&mut seed);

        sodalite::sign_keypair_seed(&mut pk, &mut sk, &seed);
        tweetnacl::sign_keypair_seed(&mut pk2, &mut sk2, &seed);

        assert_eq!(&pk[..], &pk2[..]);
        assert_eq!(&sk[..], &sk2[..]);

        let n = len + sodalite::SIGN_LEN;
        let mut out1 = vec![0u8;n];
        sodalite::sign_attached(&mut out1, &m, &sk);
        let mut out2 = vec![0u8;n];
        tweetnacl::sign(&mut out2, &m, &sk);
        assert_eq!(out1, out2);

        let mut dec1 = vec![0u8;n];
        let v = sodalite::sign_attached_open(&mut dec1, &out1, &pk).unwrap();
        dec1.truncate(v);
        let mut dec2 = vec![0u8;n];
        let v = tweetnacl::sign_open(&mut dec2, &out2, &pk).unwrap();
        dec2.truncate(v);
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, m);

        /* TODO: corrupt and check the signature does not verify */
    })
}
