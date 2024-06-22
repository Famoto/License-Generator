use clap::Parser;
use libsodium_sys::*;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::io::Write;

#[derive(Parser, Debug)]
#[command(author = "Famoto", version = "1.0", about = "Hashes a binary with BLAKE2 and signs it with a given private key")]
struct Arguments {
    /// Path to the private key
    private_key: PathBuf,

    /// Path to the binary file
    binary: PathBuf,
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
    let mut hash = vec![0u8; crypto_generichash_BYTES as usize];
    unsafe {
        crypto_generichash_blake2b(
            hash.as_mut_ptr(),
            hash.len(),
            binary_data.as_ptr(),
            binary_data.len() as u64,
            std::ptr::null(),
            0,
        );
    }

    // Sign the hash with the private key
    let mut signature = vec![0u8; crypto_sign_BYTES as usize];
    unsafe {
        crypto_sign_detached(
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            hash.as_ptr(),
            hash.len() as u64,
            private_key.as_ptr(),
        );
    }

    // Encode the hash as Base64 and write to hash.out
    let hash_base64 = STANDARD.encode(&hash);
    fs::write("Output/sign/hash.out", &hash_base64).expect("Failed to write hash to file");

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
