extern crate tweetnacl_sys as sys;

#[cfg(test)]
extern crate rand;

pub fn crypto_hashblocks_sha512(state: &mut [u8;64], data: &[u8]) -> usize
{
    let x = unsafe {
        sys::crypto_hashblocks_sha512_tweet(state.as_mut_ptr(), data.as_ptr(), data.len() as u64)
    };
    x as usize
}

#[test]
fn hashblocks_sha512_twice_eq() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // 1 KiB, arbitrary
    let len = rng.gen_range(std::usize::MIN, 1024);

    let mut b = vec![0u8;len];
    rng.fill_bytes(&mut b);

    let mut hash1 = [0u8;64];
    let v1 = crypto_hashblocks_sha512(&mut hash1, &b);

    let mut hash2 = [0u8;64];
    let v2 = crypto_hashblocks_sha512(&mut hash2, &b);

    assert_eq!(&hash1[..], &hash2[..]);
    assert_eq!(v1, v2);
}
