use clap::Parser;
use libsodium_sys::*;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

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
    let private_key = parse_pem(&private_key_pem).expect("Failed to parse private key");

    // Read the binary file
    let mut binary_file = fs::File::open(&args.binary).expect("Failed to open binary file");
    let mut binary_data = Vec::new();
    binary_file
        .read_to_end(&mut binary_data)
        .expect("Failed to read binary file");

    // Hash the binary data with crypto_generichash_blake2b
    let mut binary_hash = vec![0u8; crypto_generichash_BYTES as usize];
    unsafe {
        crypto_generichash_blake2b(
            binary_hash.as_mut_ptr(),
            binary_hash.len(),
            binary_data.as_ptr(),
            binary_data.len() as u64,
            std::ptr::null(),
            0,
        );
    }

    // Hash the hardware identifier
    let mut hid_hash = vec![0u8; crypto_generichash_BYTES as usize];
    unsafe {
        crypto_generichash_blake2b(
            hid_hash.as_mut_ptr(),
            hid_hash.len(),
            args.hid.as_ptr(),
            args.hid.len() as u64,
            std::ptr::null(),
            0,
        );
    }

    // Concatenate HID hash and binary hash, then hash the result
    let mut concatenated_hash_input = Vec::new();
    concatenated_hash_input.extend_from_slice(&hid_hash);
    concatenated_hash_input.extend_from_slice(&binary_hash);

    let mut concatenated_hash = vec![0u8; crypto_generichash_BYTES as usize];
    unsafe {
        crypto_generichash_blake2b(
            concatenated_hash.as_mut_ptr(),
            concatenated_hash.len(),
            concatenated_hash_input.as_ptr(),
            concatenated_hash_input.len() as u64,
            std::ptr::null(),
            0,
        );
    }

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
    let concatenated_hash_base64 = STANDARD.encode(&concatenated_hash);
    fs::write("Output/sign/hash.out", &concatenated_hash_base64).expect("Failed to write hash to file");

    // Write the binary signature to sign/sign.bin
    fs::write("Output/sign/sign.bin", &signature).expect("Failed to write signature to file");
}

fn parse_pem(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Split the PEM file into lines and filter out the header and footer
    let lines: Vec<&str> = pem
        .lines()
        .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
        .collect();

    // Join the remaining lines and decode from base64
    let base64_encoded: String = lines.join("");
    let decoded = STANDARD.decode(base64_encoded.as_bytes())?;
    Ok(decoded)
}
