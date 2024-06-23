use libsodium_sys::crypto_generichash_blake2b;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;


//const HASH_LENGTH: usize = libsodium_sys::crypto_generichash_BYTES as usize;
const HASH_LENGTH: usize = libsodium_sys::crypto_generichash_KEYBYTES_MAX as usize;

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hash = vec![0u8; HASH_LENGTH as usize];
    unsafe {
        crypto_generichash_blake2b(
            hash.as_mut_ptr(),
            hash.len(),
            data.as_ptr(),
            data.len() as u64,
            std::ptr::null(),
            0,
        );
    }
    hash
}

pub fn parse_pem(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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