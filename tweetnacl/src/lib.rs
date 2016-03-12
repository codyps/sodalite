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

pub fn crypto_stream_salsa20_xor(mut c: &mut [u8], m: Option<&[u8]>, n: &[u8], k: &[u8;32])
{
    m.map(|x| assert_eq!(x.len(), c.len()));
    unsafe {
        sys::crypto_stream_salsa20_tweet_xor(c.as_mut_ptr(), match m { Some(v) => v.as_ptr(), None => std::ptr::null() }, c.len() as sys::c_ulonglong, n.as_ptr(), k.as_ptr())
    };
}
 
pub fn crypto_onetimeauth(out: &mut [u8;16], m: &[u8], k: &[u8;32])
{
    unsafe {
        sys::crypto_onetimeauth_poly1305_tweet(out.as_mut_ptr(), m.as_ptr(), m.len() as sys::c_ulonglong, k.as_ptr())
    };
}

pub fn crypto_onetimeauth_verify(h: &[u8;16], m: &[u8], k: &[u8;32]) -> isize
{
    let x = unsafe {
        sys::crypto_onetimeauth_poly1305_tweet_verify(h.as_ptr(), m.as_ptr(), m.len() as sys::c_ulonglong, k.as_ptr())
    };
    x as isize
}

pub fn crypto_secretbox(out: &mut [u8], m: &[u8], n: &[u8;24], k: &[u8;32]) -> Result<(),()>
{
    assert_eq!(out.len(), m.len());
    let x = unsafe {
        sys::crypto_secretbox_xsalsa20poly1305_tweet(
            out.as_mut_ptr(), m.as_ptr(), m.len() as sys::c_ulonglong, n.as_ptr(), k.as_ptr()
        )
    };

    match x {
        0 => Ok(()),
        _ => Err(()),
    }
}

pub fn crypto_secretbox_open(m: &mut [u8], c: &[u8], n:&[u8;24], k:&[u8;32]) -> Result<(),()>
{
    assert_eq!(m.len(), c.len());
    let x = unsafe {
        sys::crypto_secretbox_xsalsa20poly1305_tweet_open(m.as_mut_ptr(), c.as_ptr(), m.len() as sys::c_ulonglong, n.as_ptr(), k.as_ptr())
    };

    match x {
        0 => Ok(()),
        _ => Err(()),
    }
}

pub fn crypto_stream(c: &mut [u8], n: &[u8;24], k: &[u8;32])
{
    unsafe {
        sys::crypto_stream_xsalsa20_tweet(c.as_mut_ptr(), c.len() as sys::c_ulonglong, n.as_ptr(), k.as_ptr())
    };
}

pub fn crypto_stream_xor(c: &mut [u8], m: &[u8], n: &[u8;24], k: &[u8;32])
{
    assert_eq!(c.len(), m.len());
    unsafe {
        sys::crypto_stream_xsalsa20_tweet_xor(c.as_mut_ptr(), m.as_ptr(), c.len() as sys::c_ulonglong, n.as_ptr(), k.as_ptr())
    };
}

pub fn crypto_box(c: &mut [u8], m: &[u8], n: &[u8;24], y: &[u8;32], x: &[u8;32]) -> Result<(),()>
{
    assert_eq!(c.len(), m.len());
    let x = unsafe {
        sys::crypto_box_curve25519xsalsa20poly1305_tweet(c.as_mut_ptr(),
            m.as_ptr(), m.len() as sys::c_ulonglong, n.as_ptr(), y.as_ptr(), x.as_ptr())
    };

    match x {
        0 => Ok(()),
        _ => Err(()),
    }
}

pub fn crypto_box_open(m : &mut [u8], c: &[u8], n: &[u8;24], y: &[u8;32], x: &[u8;32]) -> Result<(),()>
{
    assert_eq!(c.len(), m.len());
    let x = unsafe {
        sys::crypto_box_curve25519xsalsa20poly1305_tweet_open(m.as_mut_ptr(),
            c.as_ptr(), c.len() as sys::c_ulonglong, n.as_ptr(), y.as_ptr(), x.as_ptr())
    };

    match x {
        0 => Ok(()),
        _ => Err(()),
    }
}

pub fn crypto_scalarmult_base(q: &mut [u8;32], n: &[u8;32])
{
    unsafe {
        sys::crypto_scalarmult_curve25519_tweet_base(q.as_mut_ptr(), n.as_ptr());
    };
}

pub fn crypto_scalarmult(q: &mut [u8;32], n: &[u8;32], p: &[u8;32])
{
    unsafe {
        sys::crypto_scalarmult_curve25519_tweet(q.as_mut_ptr(), n.as_ptr(), p.as_ptr())
    };
}

pub fn crypto_sign(sm: &mut [u8], m: &[u8], sk: &[u8;64]) -> usize
{
    assert_eq!(sm.len(), m.len() + 64);
    let mut smlen : sys::c_ulonglong = sm.len() as sys::c_ulonglong;
    unsafe {
        sys::crypto_sign_ed25519_tweet(sm.as_mut_ptr(), &mut smlen, m.as_ptr(), m.len() as sys::c_ulonglong, sk.as_ptr())
    };

    smlen as usize
}

pub fn crypto_sign_open(m: &mut [u8], sm : &[u8], pk: &[u8;32]) -> Result<usize, ()>
{
    assert_eq!(m.len(), sm.len());
    let mut mlen = m.len() as sys::c_ulonglong;
    let x = unsafe {
        sys::crypto_sign_ed25519_tweet_open(m.as_mut_ptr(), &mut mlen, sm.as_ptr(), sm.len() as sys::c_ulonglong, pk.as_ptr())
    };

    match x {
        0 => Ok(mlen as usize),
        _ => Err(()),
    }
}

pub fn crypto_sign_keypair(pk: &mut [u8;32], sk: &mut [u8;64])
{
    unsafe {
        sys::crypto_sign_ed25519_tweet_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
    };
}

pub fn crypto_sign_keypair_seed(pk: &mut [u8;32], sk: &mut [u8;64], seed: &[u8;32])
{
    unsafe {
        sys::crypto_sign_ed25519_tweet_keypair_seed(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
    };
}

pub fn crypto_mod_l(r: &mut [u8;32], x: &mut [i64;64])
{
    let mut x_sys : Vec<_> = (&x[..]).iter().cloned().map(|x| x as sys::c_longlong).collect();
    unsafe {
        sys::crypto_modL_tweet(r.as_mut_ptr(), x_sys.as_mut_ptr());
    };

    for (i, v) in x_sys.into_iter().enumerate() {
        x[i] = v;
    }
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
