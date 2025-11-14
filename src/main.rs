const MAX_SECRET_LENGTH: usize = 32;
const BASE32_ALPHABET: [u8; 32] = make_base32_alphabet();

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

    &mut arr[0..idx]
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

fn main() {
    let tmp = read_secret_from_file(".2fa");
    let (offset, len): (usize, usize);
    {
        let _tmp = tmp.trim();
        offset = _tmp.as_ptr() as usize - tmp.as_ptr() as usize;
        len = _tmp.len();
        println!(
            "Received Secret: {}, Offset: {}, Len: {}",
            _tmp, offset, len
        );
        assert_ne!(len, 0);
        assert_eq!(len % 8, 0);
    }
    let mut _secret = tmp.into_bytes();
    let mut secret = &mut _secret[offset..offset + len];

    for (i, b) in secret.iter_mut().enumerate() {
        *b = BASE32_ALPHABET
            .iter()
            .position(|&x| x == *b)
            .unwrap_or_else(|| panic!("'{}' at index {} is not in Base32", *b as char, i))
            as u8;
    }
    secret = pack_base32_in_place(secret);
    println!("{:?}", secret);
}
