use std::cmp;
use std::mem;
use std::num::Wrapping;
use std::num::Wrapping as W;
extern crate rand;

#[cfg(test)]
mod test;

use rand::Rng;

type Gf = [i64;16];
const GF0 : Gf = [0; 16];
const GF1 : Gf = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

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

fn l32(x: W<u32>, c: usize /* int */) -> W<u32>
{
    (x << c) | ((x & W(0xffffffff)) >> (32 - c))
}

fn ld32(x: &[u8;4]) -> W<u32>
{
    let mut u = x[3] as u32;
    u = (u << 8) | (x[2] as u32);
    u = (u << 8) | (x[1] as u32);
    W((u << 8) | (x[0] as u32))
}

fn dl64(x: &[u8;8]) -> W<u64>
{
    let mut u = 0u64;
    for v in x {
        u = u << 8 | (*v as u64);
    }
    W(u)
}

fn st32(x: &mut [u8;4], mut u: W<u32>)
{
    for v in x.iter_mut() {
        *v = u.0 as u8;
        u = u >> 8;
    }
}

fn ts64(x: &mut [u8;8], mut u: u64)
{
    for v in x.iter_mut().rev() {
        *v = u as u8;
        u >>= 8;
    }
}

fn vn(x: &[u8], y: &[u8]) -> isize
{
    assert_eq!(x.len(), y.len());
    let mut d = 0u32;
    for i in 0..x.len() {
        d |= (x[i] ^ y[i]) as u32;
    }

    /* FIXME: check this cast. appears this function might be attempting to sign extend. This also
     * affects a bunch of other functions that right now have isize as a return type */
    ((W(1) & ((W(d) - W(1)) >> 8)) - W(1)).0 as isize
}

pub fn crypto_verify_16(x: &[u8;16], y: &[u8;16]) -> isize
{
    vn(&x[..], &y[..])
}

pub fn crypto_verify_32(x: &[u8;32], y: &[u8;32]) -> isize
{
    vn(&x[..], &y[..])
}

macro_rules! index_n {
    ($name:ident $name_mut:ident $ct:expr) => {
        #[allow(dead_code)]
        fn $name<T>(a: &[T]) -> &[T;$ct] {
            let x = &a[..$ct];
            unsafe { mem::transmute(x.as_ptr()) }
        }

        #[allow(dead_code)]
        fn $name_mut<T>(a: &mut [T]) -> &mut [T;$ct] {
            let x = &mut a[..$ct];
            unsafe { mem::transmute(x.as_mut_ptr()) }
        }
    }
}

index_n! {index_4 index_mut_4 4}
index_n! {index_8 index_mut_8 8}
index_n! {index_16 index_mut_16 16}
index_n! {index_32 index_mut_32 32}

fn core(out: &mut[u8], inx: &[u8;16], k: &[u8;32], c: &[u8;16], h: bool)
{
    let mut w = [W(0u32); 16];
    let mut x = [W(0u32); 16];
    let mut y = [W(0u32); 16];
    let mut t = [W(0u32); 4];

    for i in 0..4 {
        x[5*i] = ld32(index_4(&c[4*i..]));
        x[1+i] = ld32(index_4(&k[4*i..]));
        x[6+i] = ld32(index_4(&inx[4*i..]));
        x[11+i] = ld32(index_4(&k[16+4*i..]));
    }

    for i in 0..16 {
        y[i] = x[i];
    }

    for _ in 0..20 {
        for j in 0..4 {
            for m in 0..4 {
                t[m] = x[(5*j+4*m)%16];
            }
            t[1] = t[1] ^ l32(t[0]+t[3], 7);
            t[2] = t[2] ^ l32(t[1]+t[0], 9);
            t[3] = t[3] ^ l32(t[2]+t[1],13);
            t[0] = t[0] ^ l32(t[3]+t[2],18);
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
            x[i] = x[i] + y[i];
        }
        for i in 0..4 {
            x[5*i] = x[5*i] - ld32(index_4(&c[4*i..]));
            x[6+i] = x[6+i] - ld32(index_4(&inx[4*i..]));
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

pub fn crypto_core_salsa20(out: &mut [u8;64], inx: &[u8;16], k: &[u8;32], c: &[u8;16])
{
    core(out,inx,k,c,false);
}

pub fn crypto_core_hsalsa20(out: &mut [u8;32], inx: &[u8;16], k: &[u8;32], c: &[u8;16])
{
    core(out,inx,k,c,true);
}

static SIGMA : &'static [u8;16] = b"expand 32-byte k";

pub fn crypto_stream_salsa20_xor(mut c: &mut [u8], mut m: Option<&[u8]>, n: &[u8;8], k: &[u8;32])
{
    let mut z = [0u8;16];

    /* XXX: not zeroed in tweet-nacl, provided by call to crypto_core_salsa20 */
    let mut x = [0u8;64];
    m.map(|x| assert_eq!(x.len(), c.len()));

    if c.len() == 0 {
        return;
    }

    for i in 0..8 {
        z[i] = n[i];
    }

    while c.len() >= 64 {
        crypto_core_salsa20(&mut x, &mut z,k,SIGMA);
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
        c = &mut {c}[64..];
        if m.is_some() {
          m = Some(&m.unwrap()[64..])
        }
    }

    if c.len() != 0 {
        crypto_core_salsa20(&mut x, &mut z,k,SIGMA);
        for i in 0..c.len() {
          c[i] = match m {
            Some(m) => m[i],
            None    => 0
          } ^ x[i];
        }
    }
}

pub fn crypto_stream_salsa20(c: &mut [u8], n : &[u8;8], k: &[u8;32])
{
    crypto_stream_salsa20_xor(c, None, n, k)
}

pub fn crypto_stream(c: &mut [u8], n: &[u8;24], k: &[u8;32])
{
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s,index_16(&n[..]),k,SIGMA);
    crypto_stream_salsa20(c,index_8(&n[16..]),&s)
}

pub fn crypto_stream_xor(c: &mut [u8], m: &[u8], n: &[u8;24], k: &[u8;32])
{
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s,index_16(&n[..]),k,SIGMA);
    crypto_stream_salsa20_xor(c,Some(m),index_8(&n[16..]), &s)
}

fn add1305(h: &mut [u32; 17], c: &[u32; 17])
{
    let mut u = 0u32;
    for j in 0..17 {
        u += h[j] + c[j];
        h[j] = u & 255;
        u >>= 8;
    }
}

const MINUSP : [u32;17] = [
    5u32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
];

/* poly1305 */
pub fn crypto_onetimeauth(out: &mut [u8;16], mut m: &[u8], k: &[u8;32])
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

    while m.len() > 0 {
        for j in  0..17 {
            c[j] = 0;
        }

        let j_end = cmp::min(m.len(), 16);
        for j in 0..j_end {
            c[j] = m[j] as u32;
        }
        c[j_end] = 1;
        m = &m[j_end..];
        add1305(&mut h, &c);
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
    add1305(&mut h, &MINUSP);
    /* XXX: check signed cast */
    let s : u32 = (-((h[16] >> 7) as i32)) as u32;
    for j in 0..17 {
        h[j] ^= s & (g[j] ^ h[j]);
    }

    for j in 0..16 {
        c[j] = k[j + 16] as u32;
    }
    c[16] = 0;
    add1305(&mut h, &c);
    for j in 0..16 {
        out[j] = h[j] as u8;
    }
}

pub fn crypto_onetimeauth_verify(h: &[u8;16], m: &[u8], k: &[u8;32]) -> isize /* int */
{
    let mut x = [0u8; 16];
    crypto_onetimeauth(&mut x,m,k);
    crypto_verify_16(h,&x)
}

pub fn crypto_secretbox(c: &mut [u8], m: &[u8], n: &[u8;24], k: &[u8;32]) -> Result<(),()>
{
    assert_eq!(c.len(), m.len());
    /* first 32 bytes must be zero */
    assert_eq!(&m[0..32], &[0u8;32]);

    crypto_stream_xor(c,m,n,k);
    let mut o = [0u8;16];
    {
        /* XXX: we avoid aliasing to make rust happy at the cost of an extra copy via @o */
        let (c_k, c_m) = c.split_at(32);
        crypto_onetimeauth(&mut o, c_m, index_32(c_k));
    }
    *index_mut_16(&mut c[16..32]) = o;
    *index_mut_16(c) = [0u8;16];

    Ok(())
}

/*
 * c: &[u8:d]
 */
pub fn crypto_secretbox_open(m: &mut [u8], c: &[u8], n: &[u8;24], k: &[u8;32]) -> Result<(),()>
{
    assert_eq!(m.len(), c.len());
    if c.len() < 32 {
        return Err(());
    }
    let mut x = [0u8; 32];
    crypto_stream(&mut x,n,k);
    if crypto_onetimeauth_verify(index_16(&c[16..]), &c[32..], &x) != 0 {
        return Err(());
    }
    crypto_stream_xor(m,c,n,k);
    for i in 0..32 {
        m[i] = 0;
    }
    Ok(())
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

fn pack25519(o: &mut [u8;32], n: Gf)
{
    /* XXX: uninit in tweet-nacl */
    let mut m : Gf = GF0;

    let mut t : Gf = n;
    for i in 0..16 {
        t[i] = n[i];
    }
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
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

/* "add" */
fn gf_add(o: &mut Gf, a: Gf, b: Gf)
{
    for i in 0..16 {
        o[i]=a[i]+b[i];
    }
}

/* "subtract" */
fn gf_sub(o: &mut Gf, a: Gf, b: Gf)
{
    for i in 0..16 {
        o[i]=a[i]-b[i];
    }
}

/* "multiply" */
fn gf_mult(o: &mut Gf, a: Gf, b: Gf)
{
    let mut t = [0i64;31];
    for i in 0..16 {
        for j in 0..16 {
            t[i+j]+=a[i]*b[j];
        }
    }
    for i in 0..15 {
        t[i]+=38*t[i+16];
    }
    for i in 0..16 {
        o[i]=t[i];
    }
    car25519(o);
    car25519(o);
}

/* "square" */
fn gf_square(o: &mut Gf, a: Gf)
{
    gf_mult(o,a,a);
}

fn inv25519(o: &mut Gf, i: Gf)
{
    let mut c = GF0;
    for a in 0..16 {
        c[a]=i[a];
    }
    for a in (0..254).rev() {
        /* XXX: avoid aliasing with a copy */
        let mut tmp = GF0;
        gf_square(&mut tmp,c);
        if a!=2 && a!=4 {
            gf_mult(&mut c,tmp,i);
        } else {
            c = tmp;
        }
    }
    for a in 0..16 {
        o[a]=c[a];
    }
}

fn pow2523(o: &mut Gf, i: Gf)
{
    let mut c = GF0;
    for a in 0..16 {
        c[a]=i[a];
    }
    for a in (0..251).rev() {
        /* XXX: avoid aliasing with a copy */
        let mut tmp = GF0;
        gf_square(&mut tmp,c);
        if a != 1 {
            gf_mult(&mut c,tmp,i);
        } else {
            c = tmp;
        }
    }
    for a in 0..16 {
        o[a]=c[a];
    }
}

pub fn crypto_scalarmult(q: &mut [u8;32], n: &[u8;32], p: &[u8;32])
{
    let mut z = *n;
    /* TODO: not init in tweet-nacl */
    let mut x = [0i64;80];

    let mut a = GF0;
    let mut c = a;
    let mut d = a;
    /* TODO: not init in tweet-nacl { */
    let mut e = a;
    let mut f = a;
    /* } */

    z[31]=(n[31]&127)|64;
    z[0]&=248;
    unpack25519(index_mut_16(&mut x),p);
    /* TODO: not init in tweet-nacl */
    let mut b = GF0;
    for i in 0..16 {
        b[i] = x[i];
    }

    a[0]=1;
    d[0]=1;
    for i in (0..255).rev() {
        let r: u8 = (z[i>>3]>>(i&7))&1;
        sel25519(&mut a, &mut b, r as isize);
        sel25519(&mut c, &mut d, r as isize);

        /* XXX: avoid aliasing with an extra copy */
        let mut tmp = GF0;
        gf_add(&mut e,a,c);
        gf_sub(&mut tmp,a,c);
        a = tmp;
        gf_add(&mut c,b,d);
        gf_sub(&mut tmp,b,d);
        b = tmp;
        gf_square(&mut d,e);
        gf_square(&mut f,a);
        gf_mult(&mut tmp,c,a);
        a = tmp;
        gf_mult(&mut c,b,e);
        gf_add(&mut e,a,c);
        gf_sub(&mut tmp,a,c);
        a = tmp;
        gf_square(&mut b,a);
        gf_sub(&mut c,d,f);
        gf_mult(&mut a,c,_121665);
        gf_add(&mut tmp,a,d);
        a = tmp;
        gf_mult(&mut tmp,c,a);
        c = tmp;
        gf_mult(&mut a,d,f);
        gf_mult(&mut d,b, *index_16(&x));
        gf_square(&mut b,e);
        sel25519(&mut a, &mut b, r as isize);
        sel25519(&mut c, &mut d, r as isize);
    }
    for i in 0..16 {
        x[i+16]=a[i];
        x[i+32]=c[i];
        x[i+48]=b[i];
        x[i+64]=d[i];
    }
    /* XXX: avoid aliasing with an extra copy */
    let mut tmp = [0i64;16];
    inv25519(&mut tmp, *index_16(&x[32..]));
    *index_mut_16(&mut x[32..]) = tmp;

    /* XXX: avoid aliasing with an extra copy */
    gf_mult(&mut tmp, *index_16(&x[16..]), *index_16(&x[32..]));
    *index_mut_16(&mut x[16..]) = tmp;
    pack25519(q, *index_16(&x[16..]));
}

pub fn crypto_scalarmult_base(q: &mut [u8;32], n: &[u8;32])
{
    crypto_scalarmult(q, n, &_9)
}

pub fn crypto_box_keypair(y: &mut[u8;32], x: &mut[u8;32])
{
    randombytes(&mut x[..32]);
    crypto_scalarmult_base(y,x)
}

pub fn crypto_box_beforenm(k: &mut[u8;32], y: &[u8;32], x: &[u8;32])
{
    /* TODO: uninit in tweet-nacl */
    let mut s = [0u8; 32];
    crypto_scalarmult(&mut s,x,y);
    crypto_core_hsalsa20(k, &_0, &s, SIGMA)
}

pub fn crypto_box_afternm(c: &mut[u8], m: &[u8], n: &[u8;24], k: &[u8;32]) -> Result<(),()>
{
    crypto_secretbox(c,m,n,k)
}

pub fn crypto_box_open_afternm(m: &mut[u8], c: &[u8], n: &[u8;24], k: &[u8;32]) -> Result<(),()>
{
    crypto_secretbox_open(m,c,n,k)
}

pub fn crypto_box(c: &mut [u8], m: &[u8], n: &[u8;24], y: &[u8;32], x: &[u8;32]) -> Result<(),()>
{
    assert_eq!(&m[..32], &[0u8;32]);
    /* FIXME: uninit in tweet-nacl */
    let mut k = [0u8; 32];
    crypto_box_beforenm(&mut k,y,x);
    crypto_box_afternm(c,m,n, &k)
}

pub fn crypto_box_open(m : &mut [u8], c: &[u8], n: &[u8;24], y: &[u8;32], x: &[u8;32]) -> Result<(),()>
{
    assert_eq!(&c[..16], &[0u8;16]);
    /* FIXME: k was not zeroed */
    let mut k = [0u8; 32];
    crypto_box_beforenm(&mut k,y,x);
    crypto_box_open_afternm(m,c,n, &k)
}

fn r(x: W<u64>, c: usize) -> W<u64> { (x >> c) | (x << (64 - c)) } 
fn ch(x: W<u64>, y: W<u64>, z: W<u64>) -> W<u64> { (x & y) ^ (!x & z) }
fn maj(x: W<u64>, y: W<u64>, z: W<u64>) -> W<u64> { (x & y) ^ (x & z) ^ (y & z) }
fn upper_sigma0(x: W<u64>) -> W<u64> { r(x,28) ^ r(x,34) ^ r(x,39) }
fn upper_sigma1(x: W<u64>) -> W<u64> { r(x,14) ^ r(x,18) ^ r(x,41) }
fn sigma0(x: W<u64>) -> W<u64> { r(x, 1) ^ r(x, 8) ^ (x >> 7) }
fn sigma1(x: W<u64>) -> W<u64> { r(x,19) ^ r(x,61) ^ (x >> 6) }

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

fn crypto_hashblocks(x: &mut[u8], mut m: &[u8]) -> usize
{
    /* XXX: all uninit in tweet-nacl */
    let mut z = [Wrapping(0u64);8];
    let mut b = [Wrapping(0u64);8];
    let mut a = [Wrapping(0u64);8];
    let mut w = [Wrapping(0u64);16];

    for i in 0..8 {
        let v = dl64(index_8(&x[8 * i..]));
        z[i] = v;
        a[i] = v;
    }

    while m.len() >= 128 {
        for i in 0..16 {
            w[i] = dl64(index_8(&m[8 * i..]));
        }

        for i in 0..80 {
            for j in 0..8 {
                b[j] = a[j];
            }
            let t = a[7] + upper_sigma1(a[4]) + ch(a[4],a[5],a[6]) + W(K[i]) + w[i%16];
            b[7] = t + upper_sigma0(a[0]) + maj(a[0],a[1],a[2]);
            b[3] = b[3] + t;
            for j in 0..8 {
                a[(j+1)%8] = b[j];
            }
            if i%16 == 15 {
                for j in 0..16 {
                    w[j] = w[j] + w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
                }
            }
        }

        for i in 0..8 {
            a[i] = a[i] + z[i];
            z[i] = a[i];
        }

        m = &m[128..];
    }

    for i in 0..8 {
        ts64(index_mut_8(&mut x[8*i..]),z[i].0);
    }

    m.len()
}

const IV:[u8; 64] = [
    0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
    0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
    0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
    0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
    0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
    0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
    0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
    0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
];

pub fn crypto_hash(out: &mut [u8], mut m: &[u8])
{
    /* XXX: uninit in tweet-nacl */
    let mut h = IV;

    let b = m.len();

    crypto_hashblocks(&mut h, m);
    // slice m to the last 'new_len' bytes
    let new_len = m.len() & 127;
    let s = m.len() - new_len;
    m = &m[s..][..new_len];

    let mut x = [0u8;256];
    for i in 0..m.len() {
        x[i] = m[i];
    }
    x[m.len()] = 128;

    let new_len = 256-(if m.len()<112 {128} else {0});
    let mut x = &mut x[..new_len];
    let l = x.len() - 9;
    x[l] = (b >> 61) as u8;
    /* FIXME: check cast to u64 */
    let l = x.len() - 8;
    ts64(index_mut_8(&mut x[l..]), (b<<3) as u64);
    crypto_hashblocks(&mut h, &x);

    for i in 0..64 {
        out[i] = h[i];
    }
}

fn add(p: &mut [Gf;4],q: &[Gf;4])
{
    let mut a = GF0;
    let mut b = a;
    let mut c = a;
    let mut d = a;
    let mut t = a;
    let mut e = a;
    let mut f = a;
    let mut g = a;
    let mut h = a;

    /* XXX: avoid aliasing with extra copy */
    let mut tmp = GF0;
    gf_sub(&mut a, p[1], p[0]);
    gf_sub(&mut t, q[1], q[0]);
    gf_mult(&mut tmp, a, t);
    a = tmp;
    gf_add(&mut b, p[0], p[1]);
    gf_add(&mut t, q[0], q[1]);
    gf_mult(&mut tmp, b, t);
    b = tmp;
    gf_mult(&mut c, p[3], q[3]);
    gf_mult(&mut tmp, c, D2);
    c = tmp;
    gf_mult(&mut d, p[2], q[2]);
    gf_add(&mut tmp, d, d);
    d = tmp;
    gf_sub(&mut e, b, a);
    gf_sub(&mut f, d, c);
    gf_add(&mut g, d, c);
    gf_add(&mut h, b, a);

    gf_mult(&mut p[0], e, f);
    gf_mult(&mut p[1], h, g);
    gf_mult(&mut p[2], g, f);
    gf_mult(&mut p[3], e, h);
}

fn cswap(p: &mut [Gf;4], q: &mut [Gf;4], b: u8)
{
    for i in 0..4 {
        /* FIXME: check b cast to isize */
        sel25519(&mut p[i], &mut q[i], b as isize);
    }
}

fn pack(r: &mut [u8;32], p: &[Gf;4])
{
    let mut tx = GF0;
    let mut ty = GF0;
    let mut zi = GF0;

    inv25519(&mut zi, p[2]);
    gf_mult(&mut tx, p[0], zi);
    gf_mult(&mut ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

fn scalarmult(p: &mut [Gf;4], q: &mut [Gf;4], s: &[u8])
{
    set25519(&mut p[0],GF0);
    set25519(&mut p[1],GF1);
    set25519(&mut p[2],GF1);
    set25519(&mut p[3],GF0);
    for i in (0..256).rev() {
        let b = (s[i/8]>>(i&7))&1;
        /* XXX: avoid aliasing with extra copy */
        let mut tmp = [GF0;4];
        cswap(p,q,b);
        add(q,p);
        add(&mut tmp,p);
        *p = tmp;
        cswap(p,q,b);
    }
}

fn scalarbase(p: &mut [Gf;4], s: &[u8])
{
    /* XXX: uninit */
    let mut q = [GF0; 4];
    set25519(&mut q[0],X);
    set25519(&mut q[1],Y);
    set25519(&mut q[2],GF1);
    gf_mult(&mut q[3],X,Y);
    scalarmult(p, &mut q,s);
}

pub fn crypto_sign_keypair(pk: &mut [u8;32], sk: &mut [u8;64])
{
    /* FIXME: uninit in tweet-nacl */
    let mut d = [0u8; 64];
    let mut p = [GF0;4];

    randombytes(&mut sk[..32]);
    crypto_hash(&mut d, &sk[..32]);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(&mut p,&d);
    pack(pk,&p);

    for i in 0..32 {
        sk[32 + i] = pk[i];
    }
}

const L: [u64; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

fn mod_l(r: &mut [u8], x: &mut [i64;64])
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
    let mut x = [0i64;64];
    for i in 0..64 {
        /* FIXME: this cast needs to be verified */
        x[i] = (r[i] as u64) as i64;
    }
    for i in 0..64 {
        r[i] = 0;
    }
    mod_l(r, &mut x);
}

pub fn crypto_sign(sm: &mut [u8], m: &[u8], sk: &[u8;64]) -> usize
{
    assert_eq!(sm.len(), m.len() + 64);

    let mut d = [0u8; 64];
    let mut h = [0u8; 64];
    let mut r = [0u8;64];
    let mut p = [GF0; 4];

    crypto_hash(&mut d, &sk[..32]);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    for i in 0..m.len() {
        sm[64 + i] = m[i];
    }
    for i in 0..32 {
        sm[32 + i] = d[32 + i];
    }

    crypto_hash(&mut r, &sm[32..][..m.len()+32]);
    reduce(&mut r);
    scalarbase(&mut p, &r);
    pack(index_mut_32(sm), &p);

    for i in 0..32 {
        sm[i+32] = sk[i+32];
    }
    crypto_hash(&mut h,&sm[..m.len() + 64]);
    reduce(&mut h);

    let mut x = [0i64; 64];
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
    mod_l(&mut sm[32..], &mut x);

    m.len()+64
}

fn unpackneg(r: &mut [Gf;4], p: &[u8; 32]) -> isize /* int */
{
    let mut t = GF0;
    let mut chk = t;
    let mut num = t;
    let mut den = t;
    let mut den2 = t;
    let mut den4 = t;
    let mut den6 = t;

    /* XXX: add extra copy to avoid aliasing */
    let mut tmp = GF0;

    set25519(&mut r[2],GF1);
    unpack25519(&mut r[1],p);
    gf_square(&mut num,r[1]);
    gf_mult(&mut den,num,D);
    gf_sub(&mut tmp,num,r[2]);
    num = tmp;
    gf_add(&mut tmp,r[2],den);
    den = tmp;

    gf_square(&mut den2,den);
    gf_square(&mut den4,den2);
    gf_mult(&mut den6,den4,den2);
    gf_mult(&mut t,den6,num);
    gf_mult(&mut tmp,t,den);
    t = tmp;

    pow2523(&mut tmp,t);
    t = tmp;
    gf_mult(&mut tmp,t,num);
    t = tmp;
    gf_mult(&mut tmp,t,den);
    t = tmp;
    gf_mult(&mut tmp,t,den);
    t = tmp;
    gf_mult(&mut r[0],t,den);

    gf_square(&mut chk,r[0]);
    gf_mult(&mut tmp,chk,den);
    chk = tmp;
    if neq25519(chk, num) {
        gf_mult(&mut tmp,r[0],I);
        r[0] = tmp;
    }

    gf_square(&mut chk,r[0]);
    gf_mult(&mut tmp,chk,den);
    chk = tmp;
    if neq25519(chk, num) {
        return -1;
    }

    if par25519(r[0]) == (p[31]>>7) {
        gf_sub(&mut tmp,GF0,r[0]);
        r[0] = tmp;
    }

    let (init, mut rest) = r.split_at_mut(3);
    gf_mult(&mut rest[0],init[0],init[1]);
    return 0;
}

pub fn crypto_sign_open(m: &mut [u8], sm : &[u8], pk: &[u8;32]) -> Result<usize, ()>
{
    assert_eq!(m.len(), sm.len());
    let mut t = [0u8;32];
    let mut h = [0u8;64];

    let mut p = [GF0;4];
    let mut q = p;

    if sm.len() < 64 {
        return Err(())
    }

    /* TODO: check if upackneg should return a bool */
    if unpackneg(&mut q,pk) != 0 {
        return Err(());
    }

    for i in 0..sm.len() {
        m[i] = sm[i];
    }
    for i in 0..32 {
        m[i+32] = pk[i];
    }
    crypto_hash(&mut h, &m[..sm.len()]);
    reduce(&mut h);
    scalarmult(&mut p, &mut q, &h);

    scalarbase(&mut q, &sm[32..]);
    add(&mut p, &q);
    pack(&mut t, &p);


    let n = sm.len() - 64;
    /* TODO: check if crypto_verify_32 should return a bool */
    if crypto_verify_32(index_32(sm), &t) != 0 {
        for i in 0..n {
            m[i] = 0;
        }
        return Err(());
    }

    for i in 0..n {
        m[i] = sm[i + 64];
    }
    Ok(n)
}
