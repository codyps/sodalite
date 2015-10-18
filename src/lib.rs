/*
#define FOR(i,n) for (i = 0;i < n;++i)
#define sv static void

typedef i64 gf[16];
extern void randombytes(u8 *,u64);

static const u8
  _0[16],
  _9[32] = {9};
static const gf
  gf0,
  gf1 = {1},
  _121665 = {0xDB41,1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};
*/

fn L32(x: u32, c: usize /* int */) -> u32
{
    (x << c) | ((x & 0xffffffff) >> (32 - c))
}

fn ld32(x: &[u8;4]) -> u32
{
    let u : u32 = x[3];
    u = (u << 8) | x[2];
    u = (u << 8) | x[1];
    (u << 8) | x[0]
}

fn dl64(x: &[u8;8]) -> u64
{
    let u = 0u64;
    for v in x {
        u = (u << 8 | v);
    }
    u
}

fn st32(x: &mut [u8;4], u: u32)
{
    for v in x.iter_mut() {
        v = u;
        u = u >> 8;
    }
}

fn ts64(x: &mut [u8],u: u64)
{
    for v in x.iter_mut().rev() {
        v = u;
        u >>= 8;
    }
}

fn vn(x: &const [u8], y: &const [u8]) -> isize /* int */
{
    assert_eq!(x.len(), y.len());
    let d = 0u32;
    for (v, w) in (x,y).zip() {
        d |= v ^ x;
    }

    (1 & ((d - 1) >> 8)) - 1
}

pub fn crypto_verify_16(x: &[u8;16], y: &[u8;16]) -> isize /* int */
{
    vn(x[..], y[..])
}

pub fn crypto_verify_32(x: &[u8;32], y: &[u8;32]) -> isize /* int */
{
    vn(x[..], y[..])
}

fn core(out : &mut[u8], inx: &[u8], k: &[u8], c: &[u8], h: isize /* int */)
{
    let w = [0u32; 16],
        x = [0u32; 16],
        y = [0u32; 16],
        t = [0u32; 4];

    for i in 0..4 {
        x[5*i] = ld32(c+4*i);
        x[1+i] = ld32(k+4*i);
        x[6+i] = ld32(in+4*i);
        x[11+i] = ld32(k+16+4*i);
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
            x[5*i] -= ld32(c+4*i);
            x[6+i] -= ld32(in+4*i);
        }
        for i in 0..4 {
            st32(out+4*i,x[5*i]);
            st32(out+16+4*i,x[6+i]);
        }
    } else {
        for i in 0..16 {
            st32(out + 4 * i,x[i] + y[i]);
        }
    }
}

pub fn crypto_core_salsa20(out: &mut [u8], inx: &[u8], k: &[u8], c: &[u8]) -> isize /* int */
{
  core(out,in,k,c,0);
  0
}

pub fn crypto_core_hsalsa20(out: &mut [u8], inx: &[u8], k: &[u8], c: &[u8]) -> isize /* int */
{
  core(out,in,k,c,1);
  0
}

static sigma = b"expand 32-byte k";

pub fn crypto_stream_salsa20_xor(c: &mut [u8], m: &[u8], b: u64, n: &[u8], k: &[u8]) -> isize /* int */
{
    let z = [0u8;16],
        x = [0u8;64];

    if !b {
        return 0;
    }

    for i in 0..16 {
        z[i] = 0;
    }

    for i in 0..8 {
        z[i] = n[i];
    }

    while b >= 64 {
        crypto_core_salsa20(x,z,k,sigma);
        for i in 0..64 {
            c[i] = (m?m[i]:0) ^ x[i]
        }
        u = 1;
        for i in 8..16 {
            u += z[i];
            z[i] = u;
            u >>= 8;
        }
        b -= 64;
        c += 64;
        if m {
            m += 64;
        }
    }
    
    if b {
        crypto_core_salsa20(x,z,k,sigma);
        for i in 0..b {
            c[i] = (m?m[i]:0) ^ x[i];
        }
    }

    return 0;
}

pub fn crypto_stream_salsa20(u8 *c,u64 d,const u8 *n,const u8 *k) -> isize /* int */
{
    crypto_stream_salsa20_xor(c,0,d,n,k)
}

pub fn crypto_stream(u8 *c,u64 d,const u8 *n,const u8 *k)
{
    let s = [0u8; 32];
    crypto_core_hsalsa20(s,n,k,sigma);
    crypto_stream_salsa20(c,d,n+16,s)
}

pub fn crypto_stream_xor(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k) -> isize /* int */
{
    let s = [0u8; 32];
    crypto_core_hsalsa20(s,n,k,sigma);
    crypto_stream_salsa20_xor(c,m,d,n+16,s)
}

fn add1305(h: &mut [u32; 16], c: &[u32; 16])
{
    let u = 0u32;
    for j in 0..17 {
        u += h[j] + c[j];
        h[j] = u & 255;
        u >>= 8;
    }
}

const minusp = {
    5u32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
} ;

pub fn crypto_onetimeauth(out: &mut [u8] m: &[u8], n: u64, k: &[u8]) -> isize /* int */
{
    let x = [0u32;17],
        r = [0u32;17],
        h = [0u32;17],
        c = [0u32;17],
        g = [0u32;17];

    for j in 0..16 {
        r[j]=k[j];
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

        for j in 0..min(n, 16) {
            c[j] = m[j];
        }
        c[j] = 1;
        m += j;
        n -= j;
        add1305(h,c);
        for i in 0..17 {
            x[i] = 0;
            for j in 0..17 {
                x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
            }
        }

        for i in 0..17 {
            h[i] = x[i];
        }
        let u = 0u32;
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
    add1305(h,minusp);
    let s : u32 = -(h[16] >> 7);
    for j in 0..17 {
        h[j] ^= s & (g[j] ^ h[j]);
    }

    for j in 0..16 {
       c[j] = k[j + 16];
    }
    c[16] = 0;
    add1305(h,c);
    for j in 0..16 {
        out[j] = h[j];
    }
    return 0;
}

pub fn crypto_onetimeauth_verify(h: &[u8], m: &[u8], n: u64, k: &[u8]) -> isize /* int */
{
    let x = [0u8; 16];
    crypto_onetimeauth(&mut x,m,n,k);
    return crypto_verify_16(h,&x);
}

pub fn crypto_secretbox(c: &mut [u8], m &[u8], d: u64, n: &[u8], k: &[u8]) -> isize /* int */
{
    if d < 32 {
        return -1;
    }

    crypto_stream_xor(c,m,d,n,k);
    crypto_onetimeauth(c + 16,c + 32,d - 32,c);
    for i in 0..16 {
        c[i] = 0;
    }
    return 0;
}

pub fn crypto_secretbox_open(m: &mut [u8], c: &[u8], u64 d, n: &[u8], k: &[u8]) -> isize /* int */
{
    if d < 32 {
        return -1;
    }
    let x = [0u8; 32];
    crypto_stream(&mut x,32,n,k);
    if crypto_onetimeauth_verify(c + 16,c + 32,d - 32,x) != 0 {
        return -1;
    }
    crypto_stream_xor(m,c,d,n,k);
    for i in 0..32 {
        m[i] = 0;
    }
    0
}

fn set25519(r: mut gf, a: gf)
{
    for i in 0..16 {
        r[i]=a[i];
    }
}

fn car25519(o: mut gf)
{
    for i in 0..16 {
        o[i]+=(1LL<<16);
        let c = o[i]>>16;
        o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
        o[i]-=c<<16;
    }
}

fn sel25519(p: mut gf,q: mut gf, b: isize /* int */)
{
    let c : i64 = ~(b - 1);
    for i in 0..16 {
        let t = c & (p[i]^q[i]);
        p[i]^=t;
        q[i]^=t;
    }
}

fn pack25519(o: &mut [u8], n: gf)
{
    int i,j,b;
    gf m,t;
    for i in 0..16 {
        t[i] = n[i];
    }
    car25519(t);
    car25519(t);
    car25519(t);
    for j in 0..2 {
        m[0]=t[0]-0xffed;
        for(i=1;i<15;i++) {
            m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
            m[i-1]&=0xffff;
        }
        m[15]=t[15]-0x7fff-((m[14]>>16)&1);
        b=(m[15]>>16)&1;
        m[14]&=0xffff;
        sel25519(t,m,1-b);
    }
    for i in 0..16 {
        o[2*i]=t[i]&0xff;
        o[2*i+1]=t[i]>>8;
    }
}

fn neq25519(a: gf, b: gf) -> isize /* int */
{
    let c = [u8; 32],
        d = [u8; 32];
    pack25519(c,a);
    pack25519(d,b);
    crypto_verify_32(c,d)
}

fn par25519(a: gf) -> u8
{
    let d = [0u8;32]
    pack25519(&mut d, a);
    return d[0]&1;
}

fn unpack25519(o: mut gf, n: &[u8])
{
    for i in 0..16 {
        o[i]=n[2*i]+((i64)n[2*i+1]<<8);
    }
    o[15]&=0x7fff;
}

fn A(o: mut gf, a: gf, b: gf)
{
    for i in 0..16 {
        o[i]=a[i]+b[i];
    }
}

fn Z(o: mut gf, a: gf, b: gf)
{
    for i in 0..16 {
        o[i]=a[i]-b[i];
    }
}

fn M(o: mut gf, a: gf, b: gf)
{
  i64 i,j,t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

fn S(o: mut gf, a: gf)
{
  M(o,a,a);
}

fn inv25519(o: mut gf, i: gf)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

fn pow2523(o: mut gf, i: gf)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

pub fn crypto_scalarmult(q: &mut [u8], n: &[u8], p: &[u8]) -> isize /* int */
{
  u8 z[32];
  i64 x[80],r,i;
  gf a,b,c,d,e,f;
  FOR(i,31) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  FOR(i,16) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(i=254;i>=0;--i) {
    r=(z[i>>3]>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  FOR(i,16) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  inv25519(x+32,x+32);
  M(x+16,x+16,x+32);
  pack25519(q,x+16);
  return 0;
}

pub fn crypto_scalarmult_base(q: &mut [u8], n: &[u8]) -> isize /* int */
{ 
    crypto_scalarmult(q,n,_9)
}

pub fn crypto_box_keypair(y: &mut[u8], x: &mut[u8]) -> isize /* int */
{
    randombytes(x,32);
    crypto_scalarmult_base(y,x)
}

pub fn crypto_box_beforenm(k: &mut[u8], y: &[u8], x: &[u8]) -> isize /* int */
{
    let s = [u8; 32];
    crypto_scalarmult(&mut s,x,y);
    crypto_core_hsalsa20(k,_0, &s,sigma);
}

pub fn crypto_box_afternm(c: &mut[u8], m: &[u8], d: u64, n: &[u8], k: &[u8]) -> isize /* int */
{
    crypto_secretbox(c,m,d,n,k)
}

pub fn crypto_box_open_afternm(m: &mut[u8], c: &[u8], d: u64, n: &[u8], k: &[u8]) -> isize /* int */
{
    crypto_secretbox_open(m,c,d,n,k)
}

pub fn crypto_box(c: &mut [u8], m: &[u8], d: u64, n: &[u8], y: &[u8], x: &[u8]) -> isize /* int */
{
    let k = [u8; 32];
    crypto_box_beforenm(&mut k,y,x);
    crypto_box_afternm(c,m,d,n, &k)
}

pub fn crypto_box_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *y,const u8 *x) -> isize /* int */
{
    let k = [undef<u8>(); 32];
    crypto_box_beforenm(&mut k,y,x);
    crypto_box_open_afternm(m,c,d,n, &k)
}

fn R(x: u64, c: isize /* int */) -> u64 { (x >> c) | (x << (64 - c)) } 
fn Ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (~x & z) }
fn Maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }
fn Sigma0(x: u64) -> u64 { R(x,28) ^ R(x,34) ^ R(x,39) }
fn Sigma1(x: u64) -> u64 { R(x,14) ^ R(x,18) ^ R(x,41) }
fn sigma0(x: u64) -> u64 { R(x, 1) ^ R(x, 8) ^ (x >> 7) }
fn sigma1(x: u64) -> u64 { R(x,19) ^ R(x,61) ^ (x >> 6) }

static const u64 K[80] = 
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

fn crypto_hashblocks(x: &mut[u8], m: &[u8], n: u64) -> isize /* int */
{
  u64 z[8],b[8],a[8],w[16],t;
  int i,j;

  FOR(i,8) z[i] = a[i] = dl64(x + 8 * i);

  while (n >= 128) {
    FOR(i,16) w[i] = dl64(m + 8 * i);

    FOR(i,80) {
      FOR(j,8) b[j] = a[j];
      t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
      b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] += t;
      FOR(j,8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
	FOR(j,16)
	  w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
    }

    FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }

    m += 128;
    n -= 128;
  }

  FOR(i,8) ts64(x+8*i,z[i]);

  return n;
}

static const u8 iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

fn crypto_hash(out: &mut [u8], m: &[u8], n: u64) -> isize /* int */
{
  u8 h[64],x[256];
  u64 i,b = n;

  FOR(i,64) h[i] = iv[i];

  crypto_hashblocks(h,m,n);
  m += n;
  n &= 127;
  m -= n;

  FOR(i,256) x[i] = 0;
  FOR(i,n) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = b >> 61;
  ts64(x+n-8,b<<3);
  crypto_hashblocks(h,x,n);

  FOR(i,64) out[i] = h[i];

  return 0;
}

sv add(gf p[4],gf q[4])
{
  gf a,b,c,d,t,e,f,g,h;
  
  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

fn cswap(p: &[gf;4], q: &[gf;4], b: u8)
{
    for i in 0..4 {
        sel25519(p[i],q[i],b);
    }
}

fn pack(r: &mut [u8], p: &[gf;4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]); 
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

fn scalarmult(p: &[gf;4], q: &[gf;4], s: &[u8])
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

fn scalarbase(p: &[gf;4], s: &[u8])
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

pub fn crypto_sign_keypair(pk: &mut [u8], sk: &mut [u8]) -> isize /* int */
{
    let mut d = [u8; 64],
        p = [gf;4];

    randombytes(sk, 32);
    crypto_hash(&mut d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(&p,&d);
    pack(&pk,&p);

    for i in 0..32 {
        sk[32 + i] = pk[i];
    }

    0
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

fn modL(r: &mut [u8], x: &mut [i64;64])
{
  i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  FOR(j,32) x[j] -= carry * L[j];
  FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

fn reduce(r: &mut [u8])
{
  i64 x[64],i;
  FOR(i,64) x[i] = (u64) r[i];
  FOR(i,64) r[i] = 0;
  modL(r,x);
}

fn crypto_sign(sm: &mut [u8], smlen: &mut u64, m: &[u8], n: u64, sk: &[u8]) -> isize /* int */
{
    let mut d = [0u8; 64],
        h = [u8; 64],
        r = [u8;64],
        x = [i64; 64],
        p = [gf; 4];
    i64 i,j;

    crypto_hash(d, sk, 32);
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

    crypto_hash(r, sm+32, n+32);
    reduce(r);
    scalarbase(p,r);
    pack(sm,p);

    for i in 0..32 {
        sm[i+32] = sk[i+32];
    }
    crypto_hash(h,sm,n + 64);
    reduce(h);

    let x = [0u8; 64];
    for i in 0..32 {
        x[i] = (u64) r[i];
    }

    for i in 0..32 {
        for j in 0..32 {
            x[i+j] += h[i] * (u64) d[j];
        }
    }
    modL(sm + 32,x);

    0
}

fn unpackneg(r: &[gf;4], p: &[u8; 32]) -> isize /* int */
{
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return 0;
}

pub fn crypto_sign_open(m: &mut [u8], mlen: &mut u64, sm : &[u8], n : u64, pk: &[u8]) -> isize /* int */
{
  int i;
  u8 t[32],h[64];
  gf p[4],q[4];

  *mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  FOR(i,n) m[i] = sm[i];
  FOR(i,32) m[i+32] = pk[i];
  crypto_hash(h,m,n);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    FOR(i,n) m[i] = 0;
    return -1;
  }

  FOR(i,n) m[i] = sm[i + 64];
  *mlen = n;
  return 0;
}


#[test]
fn it_works() {
}
