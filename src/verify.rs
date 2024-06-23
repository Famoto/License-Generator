use clap::Parser;
use libsodium_sys::*;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::process::exit;

#[derive(Parser, Debug)]
#[command(author = "Famoto", version = "1.1", about = "Verifies a binary hash with a given public key and hardware identifier")]
struct Arguments {
    /// Path to the public key
    public_key: PathBuf,

    /// Path to the binary file
    binary: PathBuf,

    /// Path to the signature file
    signature: PathBuf,

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

    // Read the public key
    let public_key_pem = fs::read_to_string(&args.public_key).expect("Failed to read public key file");
    let public_key = parse_pem(&public_key_pem).expect("Failed to parse public key");

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

    // Encode the concatenated hash as Base64 and write to verify/hash.out
    let concatenated_hash_base64 = STANDARD.encode(&concatenated_hash);
    fs::write("Output/verify/hash.out", &concatenated_hash_base64).expect("Failed to write hash to file");

    // Read the binary signature file
    let signature = fs::read(&args.signature).expect("Failed to read signature file");

    // Verify the signature with the public key
    let is_valid = unsafe {
        crypto_sign_verify_detached(
            signature.as_ptr(),
            concatenated_hash.as_ptr(),
            concatenated_hash.len() as u64,
            public_key.as_ptr(),
        ) == 0
    };

    if is_valid {
        println!("Verification successful: The signature is valid.");
    } else {
        eprintln!("Verification failed: The signature is invalid.");
        exit(1);
    }
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
