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

fn make_byte_array(arr: &mut [u8]) {
    println!("Byte Array: {:?}", arr);
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
    }
    let secret = &mut tmp.into_bytes()[offset..offset + len];

    for (i, b) in secret.iter_mut().enumerate() {
        *b = BASE32_ALPHABET
            .iter()
            .position(|&x| x == *b)
            .unwrap_or_else(|| panic!("'{}' at index {} is not in Base32", *b as char, i))
            as u8;
    }
    make_byte_array(secret);
}
