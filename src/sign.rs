mod shared;

use clap::Parser;
use libsodium_sys::*;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use crate::shared::encode_base64;

#[derive(Parser, Debug)]
#[command(author = "Famoto", version = "1.1", about = "Hashes a binary with BLAKE2, includes a hardware identifier, and signs it with a given private key")]
struct Arguments {
    /// Path to the private key
    private_key: PathBuf,

    /// Path to the binary file
    binary: PathBuf,

    /// Hardware identifier
    hid: String,
}

fn main() {
    // Initialize libsodium
    unsafe {
        sodium_init();
    }

    // Parse CLI arguments
    let args = Arguments::parse();

    // Read the private key
    let private_key_pem = fs::read_to_string(&args.private_key).expect("Failed to read private key file");
    let private_key = shared::parse_pem(&private_key_pem).expect("Failed to parse private key");

    // Read the binary file
    let mut binary_file = fs::File::open(&args.binary).expect("Failed to open binary file");
    let mut binary_data = Vec::new();
    binary_file
        .read_to_end(&mut binary_data)
        .expect("Failed to read binary file");

    // Hash the binary data
    let binary_hash = shared::hash_data(&binary_data);

    // Hash the hardware identifier
    let hid_hash = shared::hash_data(args.hid.as_bytes());

    // Concatenate HID hash and binary hash, then hash the result
    let mut concatenated_hash_input = Vec::new();
    concatenated_hash_input.extend_from_slice(&hid_hash);
    concatenated_hash_input.extend_from_slice(&binary_hash);

    let concatenated_hash = shared::hash_data(&concatenated_hash_input);

    // Sign the concatenated hash with the private key
    let mut signature = vec![0u8; crypto_sign_BYTES as usize];
    unsafe {
        crypto_sign_detached(
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            concatenated_hash.as_ptr(),
            concatenated_hash.len() as u64,
            private_key.as_ptr(),
        );
    }

    // Encode the concatenated hash as Base64 and write to hash.out
    let concatenated_hash_base64 = encode_base64(&concatenated_hash);
    fs::write("Output/sign/hash.out", &concatenated_hash_base64).expect("Failed to write hash to file");

    // Write the binary signature to sign/sign.bin
    fs::write("Output/sign/sign.bin", &signature).expect("Failed to write signature to file");
}
