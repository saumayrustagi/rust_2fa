const MAX_SECRET_LENGTH: usize = 20;
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

fn make_byte_array(arr: &mut [u8]) {
    println!("{:?}", arr);
}

fn main() {
    let secret = std::fs::read_to_string(".2fa").unwrap();
    let secret = secret.trim();
    println!("{}, {}", str::from_utf8(&BASE32_ALPHABET).unwrap(), secret);

    let mut _arr = [0u8; MAX_SECRET_LENGTH];
    assert!(secret.len() < MAX_SECRET_LENGTH);
    let arr: &mut [u8] = &mut _arr[..secret.len()];

    for (i, &byte) in secret.as_bytes().iter().enumerate() {
        arr[i] = BASE32_ALPHABET.iter().position(|&x| x == byte).unwrap() as u8;
    }
    make_byte_array(arr);
}
