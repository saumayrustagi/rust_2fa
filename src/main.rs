const MAX_SECRET_LENGTH: usize = 32;
const BASE32_ALPHABET: [u8; 32] = make_base32_alphabet();

fn main() {
    let _secret = read_secret_from_file(".2fa");
    dbg!(&_secret);

    let (mut _secret, offset, len) = convert_secret_to_vector(_secret);
    let mut secret = &mut _secret[offset..offset + len];

    for (i, b) in secret.iter_mut().enumerate() {
        *b = BASE32_ALPHABET
            .iter()
            .position(|&x| x == *b)
            .unwrap_or_else(|| panic!("'{}' at index {} is not in Base32", *b as char, i))
            as u8;
    }
    secret = pack_base32_in_place(secret);

    println!("{}", totp(secret).unwrap_or("None".to_string()));
}

const fn make_base32_alphabet() -> [u8; 32] {
    let mut arr = [0u8; 32];
    let mut i = 0;
    while i < 26 {
        arr[i] = b'A' + i as u8;
        i += 1;
    }
    i = 0;
    while i < 6 {
        arr[26 + i] = b'2' + i as u8;
        i += 1;
    }
    return arr;
}

fn pack_base32_in_place(arr: &mut [u8]) -> &mut [u8] {
    const BASE32_SIZE: u8 = 5;
    const BYTE_SIZE: u8 = 8;

    let mut idx: usize = 0;

    let mut byte_accum = 0u16;
    let mut bits_left = 0u8;

    for i in 0..arr.len() {
        byte_accum = byte_accum << BASE32_SIZE | arr[i] as u16;
        bits_left += BASE32_SIZE;

        // print!("{:08b} ", arr[i]);

        while bits_left >= BYTE_SIZE {
            let byte: u8 = (byte_accum >> (bits_left - BYTE_SIZE)) as u8;
            // println!("=> {:08b} ", byte);
            (*arr)[idx] = byte;
            idx += 1;
            bits_left -= BYTE_SIZE;
        }
    }

    &mut (*arr)[0..idx]
}

fn read_secret_from_file(path: &str) -> String {
    use std::fs;
    use std::io::Read;

    let mut buf = vec![0u8; MAX_SECRET_LENGTH];

    let mut file = fs::File::open(path).expect("Failed to open file");
    let bytes_read = file.read(&mut buf).expect("Error reading from file");
    buf.truncate(bytes_read);

    let mut secret = String::from_utf8(buf).expect("Expected UTF-8 string");
    if let Some(first) = secret.lines().next() {
        secret.truncate(first.len());
    }

    secret
}

fn convert_secret_to_vector(secret: String) -> (Vec<u8>, usize, usize) {
    let trimmed = secret.trim();
    assert_ne!(trimmed.len(), 0, "String cannot be empty");
    assert_eq!(trimmed.len() % 8, 0);

    let offset = trimmed.as_ptr() as usize - secret.as_ptr() as usize;
    let len = trimmed.len();

    (secret.into_bytes(), offset, len)
}

mod hmac_util {
    #[inline]
    pub fn pad_vec_with_zeroes(v: &mut Vec<u8>, ideal_size: usize) {
        if ideal_size < v.len() {
            let tmp = compute_sha1(&v);
            v.copy_from_slice(&tmp);
            v.truncate(tmp.len());
        }
        v.resize(ideal_size, 0u8);
    }

    #[inline]
    pub fn xor_vec_with_mask(v: &mut Vec<u8>, mask: u8) {
        for b in v.iter_mut() {
            *b ^= mask;
        }
    }

    #[inline]
    pub fn compute_sha1(data: &[u8]) -> [u8; 20] {
        use sha1_smol::Sha1;
        let mut tmp_sha = Sha1::new();
        tmp_sha.update(data);
        tmp_sha.digest().bytes()
    }
}

fn hmac_sha1(k: Vec<u8>, c: [u8; 8]) -> [u8; 20] {
    use hmac_util as util;

    const B: usize = 64;

    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    let mut k_dash = k;
    util::pad_vec_with_zeroes(&mut k_dash, B);

    // inner_hash = sha1 (k' ^ IPAD || c)
    let mut k_xor_i = k_dash;
    util::xor_vec_with_mask(&mut k_xor_i, IPAD);
    k_xor_i.extend_from_slice(&c);
    let inner_hash = util::compute_sha1(&k_xor_i);

    // outer hash = sha1 (k' ^ OPAD || inner_hash)
    let mut k_xor_opad = k_xor_i;
    k_xor_opad.truncate(B);
    util::xor_vec_with_mask(&mut k_xor_opad, IPAD ^ OPAD);
    k_xor_opad.extend_from_slice(&inner_hash);
    let outer_hash = util::compute_sha1(&k_xor_opad);

    return outer_hash;
}

fn trcate(byte_arr: [u8; 20]) {
    assert_eq!(byte_arr.len(), 20);
}

fn hotp(k: Vec<u8>, c: [u8; 8]) {
    trcate(hmac_sha1(k, c));
}

fn be(n: u64) -> [u8; 8] {
    let mut arr = [0u8; 8];

    for i in 0..=7usize {
        arr[i] = ((n >> (i * 8)) & 0xFF) as u8;
    }

    return arr;
}

fn totp(k: &mut [u8]) -> Option<String> {
    use std::time::SystemTime;

    let x = 30u64;
    let t0 = 0u64;
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let t = (current_time - t0) / x;

    dbg!(t);

    let new_vec = k.to_vec();

    hotp(new_vec, be(t));
    return None;
}

#[cfg(test)]
mod basic_tests {
    use super::*;

    #[test]
    fn test_be_for_vals() {
        for i in (0..=56).step_by(8) {
            assert_eq!(
                {
                    let mut t = be(1 << (63 - i));
                    t.reverse();
                    t
                },
                be(1 << (7 + i))
            );
        }
    }
}

#[cfg(test)]
mod hmac_sha1_tests {
    use super::hmac_sha1;

    fn reference_hmac(key: &[u8], msg: &[u8; 8]) -> [u8; 20] {
        use hmac::digest::{KeyInit, Update};
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1Ref = Hmac<Sha1>;

        let mut mac = <HmacSha1Ref as KeyInit>::new_from_slice(key).unwrap();
        Update::update(&mut mac, msg);

        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 20];
        out.copy_from_slice(&result);
        out
    }

    fn compare(key: Vec<u8>, msg: [u8; 8]) -> bool {
        let expected = reference_hmac(&key, &msg);
        let got = hmac_sha1(key, msg);
        expected == got
    }

    #[test]
    fn test_hmac() {
        assert!(compare(vec![0x0b; 20], *b"12345678"));
        assert!(compare(b"Jefe".to_vec(), *b"ABCDEFGH"));
        assert!(compare(
            vec![0x55; 37],
            [0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4]
        ));
        assert!(compare(vec![], *b"XXXXXXXX"));
        assert!(compare(vec![0x11; 64], *b"87654321"));
    }
}
