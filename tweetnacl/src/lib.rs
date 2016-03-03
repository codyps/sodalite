extern crate tweetnacl_sys as sys;

#[cfg(test)]
extern crate rand;

pub fn crypto_hashblocks_sha512(state: &mut [u8;64], data: &[u8]) -> usize
{
    let x = unsafe {
        sys::crypto_hashblocks_sha512_tweet(state.as_mut_ptr(), data.as_ptr(), data.len() as sys::c_ulonglong)
    };
    x as usize
}

pub fn crypto_hash_sha512(out: &mut [u8;64], data: &[u8])
{
    unsafe {
        sys::crypto_hash_sha512_tweet(out.as_mut_ptr(), data.as_ptr(), data.len() as sys::c_ulonglong)
    };
}

pub fn crypto_core_salsa20(out: &mut [u8], inx: &[u8], k: &[u8], c: &[u8])
{
    unsafe {
        sys::crypto_core_salsa20_tweet(out.as_mut_ptr(), inx.as_ptr(), k.as_ptr(), c.as_ptr());
    };
}

pub fn crypto_core_hsalsa20(out: &mut [u8], inx: &[u8], k: &[u8], c: &[u8])
{
    unsafe {
        sys::crypto_core_hsalsa20_tweet(out.as_mut_ptr(), inx.as_ptr(), k.as_ptr(), c.as_ptr());
    };
}

pub fn crypto_stream_salsa20_xor(mut c: &mut [u8], m: Option<&[u8]>, b: usize, n: &[u8], k: &[u8;32])
{
    unsafe {
        sys::crypto_stream_salsa20_tweet_xor(c.as_mut_ptr(), match m { Some(v) => v.as_ptr(), None => std::ptr::null() }, b as sys::c_ulonglong, n.as_ptr(), k.as_ptr())
    };
}
 
pub fn crypto_onetimeauth(out: &mut [u8;16], m: &[u8], k: &[u8;32])
{
    unsafe {
        sys::crypto_onetimeauth_poly1305_tweet(out.as_mut_ptr(), m.as_ptr(), m.len() as sys::c_ulonglong, k.as_ptr())
    };
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
