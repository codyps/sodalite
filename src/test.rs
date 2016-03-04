/*
 * Use sodiumoxide to verify ourselves
 */
extern crate sodiumoxide;
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
    let v1 = super::crypto_hashblocks(&mut hash1, &b);

    let mut hash2 = [0u8;64];
    let v2 = tweetnacl::crypto_hashblocks_sha512(&mut hash2, &b);

    assert_eq!(&hash1[..], &hash2[..]);
    assert_eq!(v1, v2);
}

#[test]
fn hash() {
    sodiumoxide::init(); 

    let mut rng = rand::thread_rng();

    // 1 KiB, arbitrary
    let len = rng.gen_range(std::usize::MIN, 1024);
    //let len = 127;
    
    println!("length: {}", len);

    let mut b = vec![0u8;len];
    rng.fill_bytes(&mut b);

    let mut hash1 = [0u8;64];
    super::crypto_hash(&mut hash1, &b);
    let mut hash2 = [0u8;64];
    tweetnacl::crypto_hash_sha512(&mut hash2, &b);

    assert_eq!(&hash1[..], &hash2[..]);

    let hash3 = sodiumoxide::crypto::hash::hash(&b);

    assert_eq!(&hash1[..], &hash3.0[..]);
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
    super::crypto_core_salsa20(&mut out1, &inx, &k, &c);
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
    super::crypto_core_hsalsa20(&mut out1, &inx, &k, &c);
    let mut out2 = [0u8;32];
    tweetnacl::crypto_core_hsalsa20(&mut out2, &inx, &k, &c);
    assert_eq!(&out1[..], &out2[..]);
}

#[test]
fn stream_salsa20_xor() {
    let mut rng = rand::thread_rng();

    let mut inx = [0u8;16];
    rng.fill_bytes(&mut inx);

    let mut k = [0u8;32];
    rng.fill_bytes(&mut k);

    let mut c = [0u8;32];
    rng.fill_bytes(&mut c);

    let b = rng.gen_range(0, 1024);

    let mut out1 = vec![0u8;b];
    super::crypto_stream_salsa20_xor(&mut out1, None, &k, &c);
    let mut out2 = vec![0u8;b];
    tweetnacl::crypto_stream_salsa20_xor(&mut out2, None, &k, &c);
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
    super::crypto_onetimeauth(&mut out1, &m, &k);
    let mut out2 = [0u8;16];
    tweetnacl::crypto_onetimeauth(&mut out2, &m, &k);
    assert_eq!(&out1[..], &out2[..]);


    let r1 = super::crypto_onetimeauth_verify(&out1, &m, &k);
    let r2 = tweetnacl::crypto_onetimeauth_verify(&out2, &m, &k);
    assert_eq!(r1, r2);
}

#[test]
fn secretbox() {
    let mut rng = rand::thread_rng();

    // 1024 is arbitrary, 32 is required minimum length by secretbox
    let len = rng.gen_range(32, 1024);
    println!("length: {}", len);

    let mut m = vec![0u8;len];
    rng.fill_bytes(&mut m[32..]);

    let mut n = [0u8;32];
    rng.fill_bytes(&mut n);

    let mut k = [0u8;32];
    rng.fill_bytes(&mut k);

    let mut out1 = vec![0u8;len];
    super::crypto_secretbox(&mut out1, &m, &n, &k).unwrap();
    let mut out2 = vec![0u8;len];
    tweetnacl::crypto_secretbox(&mut out2, &m, &n, &k).unwrap();
    assert_eq!(&out1[..], &out2[..]);

    let mut dec1 = vec![0u8;len];
    super::crypto_secretbox_open(&mut dec1, &out1, &n, &k).unwrap();
    let mut dec2 = vec![0u8;len];
    tweetnacl::crypto_secretbox(&mut dec2, &out2, &n, &k).unwrap();
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, m);
}
