extern crate libc;

pub use libc::{c_int,c_ulonglong};

extern {
    pub fn crypto_auth_hmacsha512256_tweet(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8) -> c_int;
    pub fn crypto_auth_hmacsha512256_tweet_verify(x: *const u8,x: *const u8,n: c_ulonglong,x: *const u8) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_open(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_keypair(out: *mut u8,out: *mut u8) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(out: *mut u8,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_afternm(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_core_salsa20_tweet(out: *mut u8,x: *const u8,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_core_hsalsa20_tweet(out: *mut u8,x: *const u8,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_hashblocks_sha512_tweet(out: *mut u8,x: *const u8,n: c_ulonglong) -> c_int;
    pub fn crypto_hashblocks_sha256_tweet(out: *mut u8,x: *const u8,n: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha512_tweet(out: *mut u8,x: *const u8,n: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha256_tweet(out: *mut u8,x: *const u8,n: c_ulonglong) -> c_int;
    pub fn crypto_onetimeauth_poly1305_tweet(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8) -> c_int;
    pub fn crypto_onetimeauth_poly1305_tweet_verify(x: *const u8,x: *const u8,n: c_ulonglong,x: *const u8) -> c_int;
    pub fn crypto_scalarmult_curve25519_tweet(out: *mut u8,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_scalarmult_curve25519_tweet_base(out: *mut u8,x: *const u8) -> c_int;
    pub fn crypto_secretbox_xsalsa20poly1305_tweet(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_secretbox_xsalsa20poly1305_tweet_open(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_sign_ed25519_tweet(out: *mut u8,n: *mut c_ulonglong,x: *const u8,n: c_ulonglong,x: *const u8) -> c_int;
    pub fn crypto_sign_ed25519_tweet_open(out: *mut u8,n: *mut c_ulonglong,x: *const u8,n: c_ulonglong,x: *const u8) -> c_int;
    pub fn crypto_sign_ed25519_tweet_keypair(out: *mut u8,out: *mut u8) -> c_int;
    pub fn crypto_stream_xsalsa20_tweet(out: *mut u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_stream_xsalsa20_tweet_xor(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_stream_salsa20_tweet(out: *mut u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_stream_salsa20_tweet_xor(out: *mut u8,x: *const u8,n: c_ulonglong,x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_verify_16_tweet(x: *const u8,x: *const u8) -> c_int;
    pub fn crypto_verify_32_tweet(x: *const u8,x: *const u8) -> c_int;
}
