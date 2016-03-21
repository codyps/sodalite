/*
 * TODO: add test vectors
 */

extern crate tweetnacl;
extern crate rand;

use rand::Rng;
use std;

#[test]
fn hashblock() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // 1 KiB, arbitrary
    let len = rng.gen_range(std::usize::MIN, 1024);

    let mut b = vec![0u8;len];
    rng.fill_bytes(&mut b);

    let mut hash1 = [0u8;64];
    let v1 = super::hashblocks(&mut hash1, &b);

    let mut hash2 = [0u8;64];
    let v2 = tweetnacl::crypto_hashblocks_sha512(&mut hash2, &b);

    assert_eq!(&hash1[..], &hash2[..]);
    assert_eq!(v1, v2);
}

#[test]
fn hash() {

    let mut rng = rand::thread_rng();

    // 1 KiB, arbitrary
    let len = rng.gen_range(std::usize::MIN, 1024);
    //let len = 127;
    
    println!("length: {}", len);

    let mut b = vec![0u8;len];
    rng.fill_bytes(&mut b);

    let mut hash1 = [0u8;64];
    super::hash(&mut hash1, &b);
    let mut hash2 = [0u8;64];
    tweetnacl::crypto_hash_sha512(&mut hash2, &b);

    assert_eq!(&hash1[..], &hash2[..]);
}

#[test]
fn  core_salsa20() {
    let mut rng = rand::thread_rng();

    let mut inx = [0u8;16];
    rng.fill_bytes(&mut inx);

    let mut k = [0u8;32];
    rng.fill_bytes(&mut k);

    let mut c = [0u8;16];
    rng.fill_bytes(&mut c);

    let mut out1 = [0u8;64];
    super::core_salsa20(&mut out1, &inx, &k, &c);
    let mut out2 = [0u8;64];
    tweetnacl::crypto_core_salsa20(&mut out2, &inx, &k, &c);
    assert_eq!(&out1[..], &out2[..]);
}

#[test]
fn  core_hsalsa20() {
    let mut rng = rand::thread_rng();

    let mut inx = [0u8;16];
    rng.fill_bytes(&mut inx);

    let mut k = [0u8;32];
    rng.fill_bytes(&mut k);

    let mut c = [0u8;16];
    rng.fill_bytes(&mut c);

    let mut out1 = [0u8;32];
    super::core_hsalsa20(&mut out1, &inx, &k, &c);
    let mut out2 = [0u8;32];
    tweetnacl::crypto_core_hsalsa20(&mut out2, &inx, &k, &c);
    assert_eq!(&out1[..], &out2[..]);
}

#[test]
fn stream_salsa20_xor() {
    let mut rng = rand::thread_rng();

    let mut inx = [0u8;16];
    rng.fill_bytes(&mut inx);

    let mut n = [0u8;8];
    rng.fill_bytes(&mut n);

    let mut c = [0u8;32];
    rng.fill_bytes(&mut c);

    // 1024 is arbitrary
    let b = rng.gen_range(0, 1024);

    let mut out1 = vec![0u8;b];
    super::stream_salsa20_xor(&mut out1, None, &n, &c);
    let mut out2 = vec![0u8;b];
    tweetnacl::crypto_stream_salsa20_xor(&mut out2, None, &n, &c);
    assert_eq!(&out1[..], &out2[..]);
}

#[test]
fn onetimeauth() {
    let mut rng = rand::thread_rng();

    let len = rng.gen_range(std::usize::MIN, 1024);
    println!("length: {}", len);

    let mut m = vec![0u8;len];
    rng.fill_bytes(&mut m);

    let mut k = [0u8;32];
    rng.fill_bytes(&mut k);

    let mut out1 = [0u8;16];
    super::onetimeauth(&mut out1, &m, &k);
    let mut out2 = [0u8;16];
    tweetnacl::crypto_onetimeauth(&mut out2, &m, &k);
    assert_eq!(&out1[..], &out2[..]);

    let r1 = super::onetimeauth_verify(&out1, &m, &k);
    let r2 = tweetnacl::crypto_onetimeauth_verify(&out2, &m, &k);
    assert_eq!(r1, r2);
}

#[test]
fn stream() {
    let mut rng = rand::thread_rng();

    let len = rng.gen_range(0, 1024);
    println!("length: {}", len);

    let mut m = vec![0u8;len];
    rng.fill_bytes(&mut m);

    let mut n = [0u8;24];
    rng.fill_bytes(&mut n);

    let mut k = [0u8;32];
    rng.fill_bytes(&mut k);

    let mut out1 = vec![0u8;len];
    super::stream(&mut out1, &n, &k);
    let mut out2 = vec![0u8;len];
    tweetnacl::crypto_stream(&mut out2, &n, &k);
    assert_eq!(&out1[..], &out2[..]);

    let mut out1 = vec![0u8;len];
    super::stream_xor(&mut out1, &m, &n, &k);
    let mut out2 = vec![0u8;len];
    tweetnacl::crypto_stream_xor(&mut out2, &m, &n, &k);
    assert_eq!(&out1[..], &out2[..]);
}

#[test]
fn scalarmult() {
    let mut rng = rand::thread_rng();

    let mut p = [0u8;32];
    rng.fill_bytes(&mut p);

    let mut q1 = [0u8;32];
    super::scalarmult_base(&mut q1, &p);
    let mut q2 = [0u8;32];
    tweetnacl::crypto_scalarmult_base(&mut q2, &p);
    assert_eq!(&q1[..], &q2[..]);
}

#[test]
fn box_() {
    let mut rng = rand::thread_rng();

    // max length is arbitrary, 32 is minimum size of crypo_box and must be zeroed.
    let len = rng.gen_range(32, 1024);
    println!("length: {}", len);

    let mut m = vec![0u8;len];
    rng.fill_bytes(&mut m[32..]);

    let mut n = [0u8;24];
    rng.fill_bytes(&mut n);

    let mut pk = [0u8;32];
    let mut sk = [0u8;32];

    super::box_keypair(&mut pk, &mut sk);

    let mut out1 = vec![0u8;len];
    super::box_(&mut out1, &m, &n, &pk, &sk).unwrap();
    let mut out2 = vec![0u8;len];
    tweetnacl::crypto_box(&mut out2, &m, &n, &pk, &sk).unwrap();
    assert_eq!(&out1[..], &out2[..]);

    let mut dec1 = vec![0u8;len];
    super::box_open(&mut dec1, &out1, &n, &pk, &sk).unwrap();
    let mut dec2 = vec![0u8;len];
    tweetnacl::crypto_box_open(&mut dec2, &out2, &n, &pk, &sk).unwrap();
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, m);


    /* TODO: "corrupt" some data and ensure it doesn't open the box */
}

#[test]
fn secretbox() {
    let mut rng = rand::thread_rng();

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
    super::secretbox(&mut out1, &m, &n, &k).unwrap();
    let mut out2 = vec![0u8;len];
    tweetnacl::crypto_secretbox(&mut out2, &m, &n, &k).unwrap();
    assert_eq!(&out1[..], &out2[..]);

    let mut dec1 = vec![0u8;len];
    super::secretbox_open(&mut dec1, &out1, &n, &k).unwrap();
    let mut dec2 = vec![0u8;len];
    tweetnacl::crypto_secretbox_open(&mut dec2, &out2, &n, &k).unwrap();
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, m);


    /* TODO: "corrupt" some data and ensure it doesn't open the box */
}

#[test]
fn sign() {
    let mut rng = rand::thread_rng();

    // max length is arbitrary
    let len = rng.gen_range(0, 1);
    println!("length: {}", len);

    let mut m = vec![0u8;len];
    rng.fill_bytes(&mut m);

    let mut pk = [0u8;32];
    let mut sk = [0u8;64];
    let mut pk2 = [0u8;32];
    let mut sk2 = [0u8;64];

    let mut seed = [0u8;32];
    rng.fill_bytes(&mut seed);

    super::sign_keypair_seed(&mut pk, &mut sk, &seed);
    tweetnacl::crypto_sign_keypair_seed(&mut pk2, &mut sk2, &seed);

    assert_eq!(&pk[..], &pk2[..]);
    assert_eq!(&sk[..], &sk2[..]);

    let n = len + 64;
    let mut out1 = vec![0u8;n];
    let v = super::sign(&mut out1, &m, &sk);
    out1.truncate(v);
    let mut out2 = vec![0u8;n];
    let v = tweetnacl::crypto_sign(&mut out2, &m, &sk);
    out2.truncate(v);
    assert_eq!(&out1[..32], &out2[..32]);
    assert_eq!(out1, out2);

    let mut dec1 = vec![0u8;n];
    let v = super::sign_open(&mut dec1, &out1, &pk).unwrap();
    dec1.truncate(v);
    let mut dec2 = vec![0u8;n];
    let v = tweetnacl::crypto_sign_open(&mut dec2, &out2, &pk).unwrap();
    dec2.truncate(v);
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, m);

    /* TODO: corrupt and check the signature does not verify */
}

#[test]
fn mod_l() {
    let mut rng = rand::thread_rng();

    // max length is arbitrary
    let len = rng.gen_range(0, 1);
    println!("length: {}", len);

    let mut r = [0u8;32];
    let mut x = [0i64;64];

    rng.fill_bytes(&mut r[..]);
    for v in x.iter_mut() {
        *v = rng.gen::<u16>() as i64;
    }

    let mut r2 = r;
    let mut x2 = x;

    super::mod_l(&mut r, &mut x);
    tweetnacl::crypto_mod_l(&mut r2, &mut x2);

    assert_eq!(&r[..], &r2[..]);
    assert_eq!(&x[..], &x2[..])

}
