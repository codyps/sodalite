/*
 * Use sodiumoxide to verify ourselves
 */
extern crate sodiumoxide;
extern crate tweetnacl;
extern crate rand;

use rand::Rng;
use std;

#[test]
fn test_hashblock() {
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
fn test_hash() {
    sodiumoxide::init(); 

    let mut rng = rand::thread_rng();

    // 1 KiB, arbitrary
    let len = rng.gen_range(std::usize::MIN, 1024);
    //let len = 1024;

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
