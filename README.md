Generates a timed OTP for 2FA.

## Details

Motivation: GitHub's [policy](https://github.blog/news-insights/product-news/raising-the-bar-for-software-security-github-2fa-begins-march-13/) requiring devs to use TOTP-based 2FA.

Language: Rust for fast & correct computation, native binaries, and portable std library.

Algorithms Implemented: [TOTP](https://datatracker.ietf.org/doc/html/rfc6238), [HOTP](https://datatracker.ietf.org/doc/html/rfc4226), [**HMAC-SHA1**](https://datatracker.ietf.org/doc/html/rfc2104)

Crates Used:
* `sha1_smol` for release
* `hmac`, `sha1` for testing

**Note**: Secret key is stored in plain-text which might be a security issue. Use a user script or change the default behaviour in main to use encrypted files.

## Building and Running

Place a file named `.r2fa` in your home (`~`) directory containing the TOTP-key. Then simply use `cargo` to run.

```console
$ cat ~/.r2fa # random base32 string sample
Z7OTEDB7O3XEO2RH
$ cargo run --release
   Compiling sha1_smol v1.0.1
   Compiling rust_2fa v0.1.0 (XXXX/rust_totp)
    Finished `release` profile [optimized] target(s) in 0.33s
     Running `target/release/rust_2fa`
28: 663754
```

The output is in the format `t: o` where `t` is the time (in seconds) remaining until this OTP is valid and `o` is the OTP.

## Extra

For this project, I focused on minimal dynamic memory-allocation. So once we get the first line of `.r2fa` as a `String`, then all subsequent operations operate directly on this one `String` (or its underlying `Vector<u8>`) until we perform SHA-1 (for which I used a crate). I learned a lot about data consumption, in-place mutation, and vector resizing due to this constraint.
Also I might upload a statically-linked binary under Releases. It would be for my personal learning and convenience only so please don't download untrusted binaries off the web.
