use std::cmp;
use std::mem;
extern crate rand;

use rand::Rng;

type Gf = [i64;16];
const GfEmpty : Gf = [0;16];
const Gf0 : Gf = [0; 16];
const Gf1 : Gf = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

const _0 : [u8;16] = [0;16];
const _9 : [u8;32] = [9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

const _121665 : Gf = [0xDB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
const D: Gf = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
const D2:Gf = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
const X: Gf = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
const Y: Gf = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
const I: Gf = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

fn randombytes(x: &mut [u8])
{
    let mut rng = rand::thread_rng();
    rng.fill_bytes(x);
}

fn L32(x: u32, c: usize /* int */) -> u32
{
    (x << c) | ((x & 0xffffffff) >> (32 - c))
}

fn ld32(x: &[u8;4]) -> u32
{
    let mut u = x[3] as u32;
    u = (u << 8) | (x[2] as u32);
    u = (u << 8) | (x[1] as u32);
    (u << 8) | (x[0] as u32)
}

fn dl64(x: &[u8;8]) -> u64
{
    let mut u = 0u64;
    for v in x {
        u = u << 8 | (*v as u64);
    }
    u
}

fn st32(x: &mut [u8;4], mut u: u32)
{
    for v in x.iter_mut() {
        *v = u as u8;
        u = u >> 8;
    }
}

fn ts64(x: &mut [u8], mut u: u64)
{
    for v in x.iter_mut().rev() {
        *v = u as u8;
        u >>= 8;
    }
}

fn vn(x: &[u8], y: &[u8]) -> u8
{
    assert_eq!(x.len(), y.len());
    let mut d = 0;
    for i in 0..x.len() {
        d |= x[i] ^ y[i];
    }

    (1 & ((d - 1) >> 8)) - 1
}

pub fn crypto_verify_16(x: &[u8;16], y: &[u8;16]) -> u8
{
    vn(&x[..], &y[..])
}

pub fn crypto_verify_32(x: &[u8;32], y: &[u8;32]) -> u8
{
    vn(&x[..], &y[..])
}

macro_rules! index_n {
    ($name:ident $name_mut:ident $ct:expr) => {
        fn $name<T>(a: &[T]) -> &[T;$ct] {
            let x = &a[0..$ct];
            unsafe { mem::transmute(x as *const [T] as *const T) }
        }

        fn $name_mut<T>(a: &mut [T]) -> &mut [T;$ct] {
            let x = &mut a[0..$ct];
            unsafe { mem::transmute(x as *mut [T] as *mut T) }
        }
    }
}

index_n! {index_4 index_mut_4 4}
index_n! {index_8 index_mut_8 8}
index_n! {index_16 index_mut_16 16}
index_n! {index_32 index_mut_32 32}

fn core(out: &mut[u8], inx: &[u8], k: &[u8], c: &[u8], h: bool)
{
    let mut w = [0u32; 16];
    let mut x = [0u32; 16];
    let mut y = [0u32; 16];
    let mut t = [0u32; 4];

    for i in 0..4 {
        x[5*i] = ld32(index_4(&c[4*i..]));
        x[1+i] = ld32(index_4(&k[4*i..]));
        x[6+i] = ld32(index_4(&inx[4*i..]));
        x[11+i] = ld32(index_4(&k[16+4*i..]));
    }

    for i in 0..16 {
        y[i] = x[i];
    }

    for i in 0..20 {
        for j in 0..4 {
            for m in 0..4 {
                t[m] = x[(5*j+4*m)%16];
            }
            t[1] ^= L32(t[0]+t[3], 7);
            t[2] ^= L32(t[1]+t[0], 9);
            t[3] ^= L32(t[2]+t[1],13);
            t[0] ^= L32(t[3]+t[2],18);
            for m in 0..4 {
                w[4*j+(j+m)%4] = t[m];
            }
        }
        for m in 0..16 {
            x[m] = w[m];
        }
    }

    if h {
        for i in 0..16 {
            x[i] += y[i];
        }
        for i in 0..4 {
            x[5*i] -= ld32(index_4(&c[4*i..]));
            x[6+i] -= ld32(index_4(&inx[4*i..]));
        }
        for i in 0..4 {
            st32(index_mut_4(&mut out[4*i..]), x[5*i]);
            st32(index_mut_4(&mut out[16+4*i..]), x[6+i]);
        }
    } else {
        for i in 0..16 {
            st32(index_mut_4(&mut out[4 * i..]), x[i] + y[i]);
        }
    }
}

pub fn crypto_core_salsa20(out: &mut [u8], inx: &[u8], k: &[u8], c: &[u8]) -> isize /* int */
{
    core(out,inx,k,c,false);
    0
}

pub fn crypto_core_hsalsa20(out: &mut [u8], inx: &[u8], k: &[u8], c: &[u8]) -> isize /* int */
{
    core(out,inx,k,c,true);
    0
}

static sigma : &'static [u8;16] = b"expand 32-byte k";

pub fn crypto_stream_salsa20_xor(mut c: &mut [u8], mut m: Option<&[u8]>, mut b: usize, n: &[u8], k: &[u8]) -> isize /* int */
{
    let mut z = [0u8;16];

    /* XXX: not zeroed in tweet-nacl, provided by call to crypto_core_salsa20 */
    let mut x = [0u8;64];

    if b == 0 {
        return 0;
    }

    for i in 0..8 {
        z[i] = n[i];
    }

    while b >= 64 {
        crypto_core_salsa20(&mut x, &mut z,k,sigma);
        for i in 0..64 {
            c[i] = match m {
              Some(m) => m[i],
              None    => 0
            } ^ x[i];
        }
        let mut u = 1u32;
        for i in 8..16 {
            u += z[i] as u32;
            z[i] = u as u8;
            u >>= 8;
        }
        b -= 64;
        c = &mut {c}[64..];
        if m.is_some() {
          m = Some(&m.unwrap()[64..])
        }
    }

    if b != 0 {
        crypto_core_salsa20(&mut x, &mut z,k,sigma);
        for i in 0..b {
          c[i] = match m {
            Some(m) => m[i],
            None    => 0
          } ^ x[i];
        }
    }

    return 0;
}

pub fn crypto_stream_salsa20(c: &mut [u8], d: usize, n : &[u8], k: &[u8]) -> isize /* int */
{
    crypto_stream_salsa20_xor(c, None ,d,n,k)
}

pub fn crypto_stream(c: &mut [u8], d: usize, n: &[u8], k: &[u8])
{
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s,n,k,sigma);
    crypto_stream_salsa20(c,d,&n[16..],&s);
}

pub fn crypto_stream_xor(c: &mut [u8], m: &[u8], d: usize, n: &[u8], k: &[u8]) -> isize /* int */
{
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s,n,k,sigma);
    crypto_stream_salsa20_xor(c,Some(m),d,&n[16..], &s)
}

fn add1305(h: &mut [u32; 16], c: &[u32; 16])
{
    let mut u = 0u32;
    for j in 0..17 {
        u += h[j] + c[j];
        h[j] = u & 255;
        u >>= 8;
    }
}

const minusp : [u32;17] = [
    5u32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
];

/*
 * m: &[u8:n]
 */
pub fn crypto_onetimeauth(out: &mut [u8;16], mut m: &[u8], mut n: usize, k: &[u8;32]) -> isize /* int */
{
    /* FIXME: not zeroed in tweet-nacl */
    let mut x = [0u32;17];
    let mut r = [0u32;17];
    let mut h = [0u32;17];
    /* FIXME: not zeroed in tweet-nacl */
    let mut c = [0u32;17];
    /* FIXME: not zeroed in tweet-nacl */
    let mut g = [0u32;17];

    for j in 0..16 {
        r[j] = k[j] as u32;
    }

    r[3]&=15;
    r[4]&=252;
    r[7]&=15;
    r[8]&=252;
    r[11]&=15;
    r[12]&=252;
    r[15]&=15;

    while n > 0 {
        for j in  0..17 {
            c[j] = 0;
        }

        let j_end = cmp::min(n, 16);
        for j in 0..j_end {
            c[j] = m[j] as u32;
        }
        c[j_end] = 1;
        m = &m[j_end..];
        n -= j_end;
        add1305(index_mut_16(&mut h), index_16(&c));
        for i in 0..17 {
            x[i] = 0;
            for j in 0..17 {
                x[i] += h[j] * (if j <= i { r[i - j] } else { 320 * r[i + 17 - j]});
            }
        }

        for i in 0..17 {
            h[i] = x[i];
        }
        let mut u = 0u32;
        for j in 0..16 {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u & 3;
        u = 5 * (u >> 2);
        for j in 0..16 {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u;
    }

    for j in 0..17 {
        g[j] = h[j];
    }
    add1305(index_mut_16(&mut h), index_16(&minusp));
    let s : u32 = -(h[16] >> 7);
    for j in 0..17 {
        h[j] ^= s & (g[j] ^ h[j]);
    }

    for j in 0..16 {
        c[j] = k[j + 16] as u32;
    }
    c[16] = 0;
    add1305(index_mut_16(&mut h), index_16(&c));
    for j in 0..16 {
        out[j] = h[j] as u8;
    }
    return 0;
}

/*
 * m: &[u8:n]
 */
pub fn crypto_onetimeauth_verify(h: &[u8;16], m: &[u8], n: usize, k: &[u8;32]) -> isize /* int */
{
    let mut x = [0u8; 16];
    crypto_onetimeauth(&mut x,m,n,k);
    crypto_verify_16(h,&x) as isize /* XXX: fixme, sizing */
}

pub fn crypto_secretbox(c: &mut [u8], m: &[u8], d: usize, n: &[u8], k: &[u8]) -> isize /* int */
{
    if d < 32 {
        return -1;
    }

    crypto_stream_xor(c,m,d,n,k);
    {
        let (c_out, c_m) = c.split_at_mut(32);
        crypto_onetimeauth(index_mut_16(&mut c_out[16..]), &c_m, d - 32, index_32(c));
    }

    for i in 0..16 {
        c[i] = 0;
    }
    return 0;
}

/*
 * c: &[u8:d]
 */
pub fn crypto_secretbox_open(m: &mut [u8], c: &[u8], d: usize, n: &[u8], k: &[u8]) -> isize /* int */
{
    if d < 32 {
        return -1;
    }
    let mut x = [0u8; 32];
    crypto_stream(&mut x,32,n,k);
    if crypto_onetimeauth_verify(index_16(&c[16..]), &c[32..], d - 32, &x) != 0 {
        return -1;
    }
    crypto_stream_xor(m,c,d,n,k);
    for i in 0..32 {
        m[i] = 0;
    }
    0
}

fn set25519(r: &mut Gf, a: Gf)
{
    for i in 0..16 {
        r[i]=a[i];
    }
}

fn car25519(o: &mut Gf)
{
    for i in 0..16 {
        o[i] += 1<<16;
        let c = o[i]>>16;
        o[if i<15 {i+1} else {0}] += c-1 + (if i==15 {37*(c-1)} else {0});
        o[i]-=c<<16;
    }
}

fn sel25519(p: &mut Gf,q: &mut Gf, b: isize /* int */)
{
    /* XXX: FIXME: check sign extention */
    let c : i64 = !(b - 1) as i64;
    for i in 0..16 {
        let t = c & (p[i]^q[i]);
        p[i]^=t;
        q[i]^=t;
    }
}

fn pack25519(o: &mut [u8], n: Gf)
{
    /* XXX: uninit in tweet-nacl */
    let mut m : Gf = GfEmpty;

    let mut t : Gf = n;
    for i in 0..16 {
        t[i] = n[i];
    }
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for j in 0..2 {
        m[0]=t[0]-0xffed;
        for i in 1..15 {
            m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
            m[i-1]&=0xffff;
        }
        m[15]=t[15]-0x7fff-((m[14]>>16)&1);
        let b=(m[15]>>16)&1;
        m[14]&=0xffff;
        /* FIXME: check isize cast here */
        sel25519(&mut t, &mut m, 1-b as isize);
    }
    for i in 0..16 {
        o[2*i]= t[i] as u8;
        o[2*i+1]= (t[i]>>8) as u8;
    }
}

fn neq25519(a: Gf, b: Gf) -> bool
{
    /* TODO: uninit in tweet-nacl */
    let mut c = [0u8; 32];

    /* TODO: uninit in tweet-nacl */
    let mut d = [0u8; 32];

    pack25519(&mut c,a);
    pack25519(&mut d,b);
    crypto_verify_32(&c, &d) != 0
}

fn par25519(a: Gf) -> u8
{
    let mut d = [0u8;32];
    pack25519(&mut d, a);
    return d[0]&1;
}

fn unpack25519(o: &mut Gf, n: &[u8])
{
    for i in 0..16 {
        o[i]=n[2*i] as i64+((n[2*i+1] as i64)<<8);
    }
    o[15]&=0x7fff;
}

fn A(o: &mut Gf, a: Gf, b: Gf)
{
    for i in 0..16 {
        o[i]=a[i]+b[i];
    }
}

fn Z(o: &mut Gf, a: Gf, b: Gf)
{
    for i in 0..16 {
        o[i]=a[i]-b[i];
    }
}

fn M(o: &mut Gf, a: Gf, b: Gf)
{
    let mut t = [0i64;31];
    for i in 0..16 {
        for j in 0..16 {
            t[i+j]+=a[i]*b[j];
        }
    }
    for i in 0..16 {
        t[i]+=38*t[i+16];
    }
    for i in 0..16 {
        o[i]=t[i];
    }
    car25519(o);
    car25519(o);
}

fn S(o: &mut Gf, a: Gf)
{
    M(o,a,a);
}

fn inv25519(o: &mut Gf, i: Gf)
{
    let mut c = GfEmpty;
    for a in 0..16 {
        c[a]=i[a];
    }
    for a in (0..254).rev() {
        S(&mut c,c);
        if a!=2 && a!=4 {
            M(&mut c,c,i);
        }
    }
    for a in 0..16 {
        o[a]=c[a];
    }
}

fn pow2523(o: &mut Gf, i: Gf)
{
    let mut c = GfEmpty;
    for a in 0..16 {
        c[a]=i[a];
    }
    for a in (0..251).rev() {
        S(&mut c,c);
        if a!=1 {
            M(&mut c,c,i);
        }
    }
    for a in 0..16 {
        o[a]=c[a];
    }
}

pub fn crypto_scalarmult(q: &mut [u8], n: &[u8], p: &[u8]) -> isize /* int */
{
    let mut z = [0u8;32];
    /* TODO: not init in tweet-nacl */
    let mut x = [0i64;80];

    /* TODO: not init in tweet-nacl { */
    let mut e = GfEmpty;
    let mut f = GfEmpty;
    /* } */
    let mut a = GfEmpty;
    let mut c = GfEmpty;
    let mut d = GfEmpty;

    z[31]=(n[31]&127)|64;
    z[0]&=248;
    unpack25519(index_mut_16(&mut x),p);
    /* TODO: not init in tweet-nacl */
    let mut b = GfEmpty;
    for i in 0..16 {
        b[i] = x[i];
    }

    a[0]=1;
    d[0]=1;
    for i in (0..255).rev() {
        let r: u8 = (z[i>>3]>>(i&7))&1;
        sel25519(&mut a, &mut b, r as isize);
        sel25519(&mut c, &mut d, r as isize);
        A(&mut e,a,c);
        Z(&mut a,a,c);
        A(&mut c,b,d);
        Z(&mut b,b,d);
        S(&mut d,e);
        S(&mut f,a);
        M(&mut a,c,a);
        M(&mut c,b,e);
        A(&mut e,a,c);
        Z(&mut a,a,c);
        S(&mut b,a);
        Z(&mut c,d,f);
        M(&mut a,c,_121665);
        A(&mut a,a,d);
        M(&mut c,c,a);
        M(&mut a,d,f);
        M(&mut d,b, *index_16(&x));
        S(&mut b,e);
        sel25519(&mut a, &mut b, r as isize);
        sel25519(&mut c, &mut d, r as isize);
    }
    for i in 0..16 {
        x[i+16]=a[i];
        x[i+32]=c[i];
        x[i+48]=b[i];
        x[i+64]=d[i];
    }
    inv25519(index_mut_16(&mut x[32..]), *index_16(&x[32..]));
    M(index_mut_16(&mut x[16..]), *index_16(&x[16..]), *index_16(&x[32..]));
    pack25519(index_mut_16(&mut q), *index_16(&x[16..]));
    return 0;
}

pub fn crypto_scalarmult_base(q: &mut [u8], n: &[u8]) -> isize /* int */
{
    crypto_scalarmult(q, n, &_9)
}

pub fn crypto_box_keypair(y: &mut[u8], x: &mut[u8]) -> isize /* int */
{
    randombytes(&mut x[..32]);
    crypto_scalarmult_base(y,x)
}

pub fn crypto_box_beforenm(k: &mut[u8], y: &[u8], x: &[u8]) -> isize /* int */
{
    /* TODO: uninit in tweet-nacl */
    let s = [0u8; 32];
    crypto_scalarmult(&mut s,x,y);
    crypto_core_hsalsa20(k, &_0, &s, sigma)
}

pub fn crypto_box_afternm(c: &mut[u8], m: &[u8], d: usize, n: &[u8], k: &[u8]) -> isize /* int */
{
    crypto_secretbox(c,m,d,n,k)
}

pub fn crypto_box_open_afternm(m: &mut[u8], c: &[u8], d: usize, n: &[u8], k: &[u8]) -> isize /* int */
{
    crypto_secretbox_open(m,c,d,n,k)
}

pub fn crypto_box(c: &mut [u8], m: &[u8], d: usize, n: &[u8], y: &[u8], x: &[u8]) -> isize /* int */
{
    /* FIXME: uninit in tweet-nacl */
    let k = [0u8; 32];
    crypto_box_beforenm(&mut k,y,x);
    crypto_box_afternm(c,m,d,n, &k)
}

pub fn crypto_box_open(m : &mut [u8], c: &[u8] ,d: usize, n: &[u8], y: &[u8], x: &[u8]) -> isize /* int */
{
    /* FIXME: k was not zeroed */
    let k = [0u8; 32];
    crypto_box_beforenm(&mut k,y,x);
    crypto_box_open_afternm(m,c,d,n, &k)
}

fn R(x: u64, c: isize /* int */) -> u64 { (x >> c) | (x << (64 - c)) } 
fn Ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (!x & z) }
fn Maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }
fn Sigma0(x: u64) -> u64 { R(x,28) ^ R(x,34) ^ R(x,39) }
fn Sigma1(x: u64) -> u64 { R(x,14) ^ R(x,18) ^ R(x,41) }
fn sigma0(x: u64) -> u64 { R(x, 1) ^ R(x, 8) ^ (x >> 7) }
fn sigma1(x: u64) -> u64 { R(x,19) ^ R(x,61) ^ (x >> 6) }

const K : [u64;80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

fn crypto_hashblocks(x: &mut[u8], mut m: &[u8], n: usize) -> usize
{
    /* XXX: all uninit in tweet-nacl */
    let z = [0u64;8];
    let b = [0u64;8];
    let a = [0u64;8];
    let w = [0u64;16];

    for i in 0..8 {
        let v = dl64(index_8(&x[8 * i..]));
        z[i] = v;
        a[i] = v;
    }

    while n >= 128 {
        for i in 0..16 {
            w[i] = dl64(index_8(&m[8 * i..]));
        }

        for i in 0..80 {
            for j in 0..8 {
                b[j] = a[j];
            }
            let t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
            b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
            b[3] += t;
            for j in 0..8 {
                a[(j+1)%8] = b[j];
            }
            if i%16 == 15 {
                for j in 0..16 {
                    w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
                }
            }
        }

        for i in 0..8 {
            a[i] += z[i]; z[i] = a[i];
        }

        m = &m[128..];
        n -= 128;
    }

    for i in 0..8 {
        ts64(&mut x[8*i..],z[i]);
    }

    n
}

const iv:[u8; 64] = [
    0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
    0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
    0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
    0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
    0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
    0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
    0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
    0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
];

pub fn crypto_hash(out: &mut [u8], mut m: &[u8], n: usize) -> isize /* int */
{
    /* XXX: uninit in tweet-nacl */
    let h = [0u8;64];
    let x = [0u8;256];

    let b = n;

    for i in 0..64 {
        h[i] = iv[i];
    }

    crypto_hashblocks(&mut h,m,n);
    let nn = n & 127;
    let s = n - nn;
    m = &m[s..];
    n = nn;

    for i in 0..256 {
        x[i] = 0;
    }
    for i in 0..n {
        x[i] = m[i];
    }
    x[n] = 128;

    n = 256-(if n<128 {128} else {0});
    x[n-9] = (b >> 61) as u8;
    /* FIXME: check cast to u64 */
    ts64(&mut x[n-8..], (b<<3) as u64);
    crypto_hashblocks(&mut h, &x,n);

    for i in 0..64 {
        out[i] = h[i];
    }

    return 0;
}

fn add(p: &[Gf;4],q: &[Gf;4])
{
    let a: Gf;
    let b: Gf;
    let c: Gf;
    let d: Gf;
    let t: Gf;
    let e: Gf;
    let f: Gf;
    let g: Gf;
    let h: Gf;

    Z(&mut a, p[1], p[0]);
    Z(&mut t, q[1], q[0]);
    M(&mut a, a, t);
    A(&mut b, p[0], p[1]);
    A(&mut t, q[0], q[1]);
    M(&mut b, b, t);
    M(&mut c, p[3], q[3]);
    M(&mut c, c, D2);
    M(&mut d, p[2], q[2]);
    A(&mut d, d, d);
    Z(&mut e, b, a);
    Z(&mut f, d, c);
    A(&mut g, d, c);
    A(&mut h, b, a);

    M(&mut p[0], e, f);
    M(&mut p[1], h, g);
    M(&mut p[2], g, f);
    M(&mut p[3], e, h);
}

fn cswap(p: &[Gf;4], q: &[Gf;4], b: u8)
{
    for i in 0..4 {
        /* FIXME: check b cast to isize */
        sel25519(&mut p[i], &mut q[i], b as isize);
    }
}

fn pack(r: &mut [u8], p: &[Gf;4])
{
    let tx: Gf;
    let ty: Gf;
    let zi: Gf;

    inv25519(&mut zi, p[2]);
    M(&mut tx, p[0], zi);
    M(&mut ty, p[1], zi);
    pack25519(&mut r, ty);
    r[31] ^= par25519(tx) << 7;
}

fn scalarmult(p: &[Gf;4], q: &[Gf;4], s: &[u8])
{
    set25519(&mut p[0],Gf0);
    set25519(&mut p[1],Gf1);
    set25519(&mut p[2],Gf1);
    set25519(&mut p[3],Gf0);
    for i in (0..256).rev() {
        let b = (s[i/8]>>(i&7))&1;
        cswap(p,q,b);
        add(q,p);
        add(p,p);
        cswap(p,q,b);
    }
}

fn scalarbase(p: &[Gf;4], s: &[u8])
{
    let q: [Gf; 4];
    set25519(&mut q[0],X);
    set25519(&mut q[1],Y);
    set25519(&mut q[2],Gf1);
    M(&mut q[3],X,Y);
    scalarmult(&mut p, &mut q,s);
}

pub fn crypto_sign_keypair(pk: &mut [u8], sk: &mut [u8]) -> isize /* int */
{
    /* FIXME: uninit in tweet-nacl */
    let mut d = [0u8; 64];
    let p :[Gf;4];

    randombytes(&mut sk[..32]);
    crypto_hash(&mut d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(&p,&d);
    pack(pk,&p);

    for i in 0..32 {
        sk[32 + i] = pk[i];
    }

    0
}

const L: [u64; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

fn modL(r: &mut [u8], x: &mut [i64;64])
{
    /*
       i64 carry,i,j;
       */
    for i in (32..64).rev() {
        let mut carry = 0;
        for j in (i - 32)..(i - 12) {
            /* FIXME: check cast to i64 */
            x[j] += carry - (16 * x[i] * L[j - (i - 32)] as i64) as i64;
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[i - 13] += carry;
        x[i] = 0;
    }

    let mut carry = 0;
    for j in 0..32 {
        /* FIXME: check cast to i64 */
        x[j] += carry - (x[31] >> 4) * L[j] as i64;
        carry = x[j] >> 8;
        x[j] &= 255;
    }

    for j in 0..32 {
        /* FIXME: check cast to i64 */
        x[j] -= carry * L[j] as i64;
    }
    for i in 0..32 {
        x[i+1] += x[i] >> 8;
        r[i] = x[i] as u8;
    }
}

fn reduce(r: &mut [u8])
{
    /* TODO: uninitialized in tweet-nacl */
    let x = [0i64;64];
    for i in 0..64 {
        /* FIXME: this cast needs to be verified */
        x[i] = (r[i] as u64) as i64;
    }
    for i in 0..64 {
        r[i] = 0;
    }
    modL(&mut r, &mut x);
}

fn crypto_sign(sm: &mut [u8], smlen: &mut usize, m: &[u8], n: usize, sk: &[u8]) -> isize /* int */
{
    let mut d = [0u8; 64];
    let mut h = [0u8; 64];
    let mut r = [0u8;64];
    let mut p = [GfEmpty; 4];

    crypto_hash(&mut d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    *smlen = n+64;
    for i in 0..n {
        sm[64 + i] = m[i];
    }
    for i in 0..32 {
        sm[32 + i] = d[32 + i];
    }

    crypto_hash(&mut r, &sm[32..], n + 32);
    reduce(&mut r);
    scalarbase(&mut p, &r);
    pack(sm, &p);

    for i in 0..32 {
        sm[i+32] = sk[i+32];
    }
    crypto_hash(&mut h,sm,n + 64);
    reduce(&mut h);

    let x = [0i64; 64];
    for i in 0..32 {
      /* FIXME: check this cast */
      x[i] = r[i] as u64 as i64;
    }

    for i in 0..32 {
        for j in 0..32 {
          /* FIXME: check this cast */
          x[i+j] += ((h[i] as u64) * (d[j] as u64)) as i64;
        }
    }
    modL(&mut sm[32..], &mut x);

    0
}

fn unpackneg(r: &[Gf;4], p: &[u8; 32]) -> isize /* int */
{
    let t:Gf;
    let chk:Gf;
    let num:Gf;
    let den:Gf;
    let den2:Gf;
    let den4:Gf;
    let den6:Gf;

    set25519(&mut r[2],Gf1);
    unpack25519(&mut r[1],p);
    S(&mut num,r[1]);
    M(&mut den,num,D);
    Z(&mut num,num,r[2]);
    A(&mut den,r[2],den);

    S(&mut den2,den);
    S(&mut den4,den2);
    M(&mut den6,den4,den2);
    M(&mut t,den6,num);
    M(&mut t,t,den);

    pow2523(&mut t,t);
    M(&mut t,t,num);
    M(&mut t,t,den);
    M(&mut t,t,den);
    M(&mut r[0],t,den);

    S(&mut chk,r[0]);
    M(&mut chk,chk,den);
    if neq25519(chk, num) {
        M(&mut r[0],r[0],I);
    }

    S(&mut chk,r[0]);
    M(&mut chk,chk,den);
    if neq25519(chk, num) {
        return -1;
    }

    if par25519(r[0]) == (p[31]>>7) {
        Z(&mut r[0],Gf0,r[0]);
    }

    M(&mut r[3],r[0],r[1]);
    return 0;
}

pub fn crypto_sign_open(m: &mut [u8], mlen: &mut usize, sm : &[u8], n : usize, pk: &[u8;32]) -> isize /* int */
{
    let t = [0u8;32];
    let h = [0u8;64];

    let p: [Gf;4];
    let q: [Gf;4];

    *mlen = -1;
    if n < 64 {
        return -1;
    }

    /* TODO: check if upackneg should return a bool */
    if unpackneg(&q,pk) != 0 {
        return -1;
    }

    for i in 0..n {
        m[i] = sm[i];
    }
    for i in 0..32 {
        m[i+32] = pk[i];
    }
    crypto_hash(&mut h,m,n);
    reduce(&mut h);
    scalarmult(&mut p, &q, &h);

    scalarbase(&mut q, &sm[32..]);
    add(&mut p, &q);
    pack(&mut t, &p);

    n -= 64;
    /* TODO: check if crypto_verify_32 should return a bool */
    if crypto_verify_32(index_32(sm), &t) != 0 {
        for i in 0..n {
            m[i] = 0;
        }
        return -1;
    }

    for i in 0..n {
        m[i] = sm[i + 64];
    }
    *mlen = n;
    return 0;
}


#[test]
fn it_works() {
}
