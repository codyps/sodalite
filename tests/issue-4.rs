use std::convert::TryInto;
use sodalite::{secretbox, secretbox_open};
const NONCE_LENGTH: usize = 24;

fn decrypt_content(key: &[u8;32], encrypted_bytes: &[u8]) -> Vec<u8> {

    let nonce: &[u8; 24] = &encrypted_bytes[0..NONCE_LENGTH].try_into().unwrap();
    println!("nonce: {}", hex::encode(nonce.clone()));
    let cipher_text = &encrypted_bytes[NONCE_LENGTH..];
    println!("cipher_text: {}", hex::encode(cipher_text.clone()));
    let mut encoded = Vec::<u8>::new();
    encoded.resize(cipher_text.len(), 0u8);

    println!("key: {}", hex::encode(key.clone()));
    let ret = secretbox_open(&mut encoded, cipher_text, nonce, &key);
    assert!(ret.is_ok(), "open secretbox failed");

    println!("encoded: {}", hex::encode(encoded.clone()));
   
    encoded.to_vec()
}

#[test]
fn a() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let mut c = [0u8;24+32+32];
        let mut m = [0u8;32+32];
        rng.fill_bytes(&mut m[32..]);
        let mut sn = [0u8;24];
        rng.fill_bytes(&mut sn);
        let mut sk = [0u8;32];
        rng.fill_bytes(&mut sk);
        secretbox(
            &mut c[24..],
            &m,
            &sn,
            &sk
        ).unwrap();

        c[..24].copy_from_slice(&sn[..]);

        let d = decrypt_content(&sk, &c);


        assert_eq!(m[..], d[..]);
    }
}
