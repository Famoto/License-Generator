use std::ffi::{CStr, CString};
use std::ffi::c_int;
use std::ptr;
use libsodium_sys::{
    crypto_generichash_blake2b,
    sodium_bin2base64,
    sodium_base64_VARIANT_ORIGINAL,
    sodium_base642bin,
};

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
    let decoded = decode_base64(base64_encoded)?;
    Ok(decoded)
}


/// Encodes the given data to a base64 string.
pub fn encode_base64(data: &[u8]) -> String {
    let b64_len = ((data.len() + 2) / 3) * 4 + 1;
    let mut b64 = vec![0u8; b64_len];
    let ret = unsafe {
        sodium_bin2base64(
            b64.as_mut_ptr() as *mut i8,
            b64_len,
            data.as_ptr(),
            data.len(),
            sodium_base64_VARIANT_ORIGINAL as c_int,
        )
    };
    assert!(!ret.is_null());
    let c_str = unsafe { CStr::from_ptr(ret) };
    c_str.to_str().unwrap().to_string()
}

/// Decodes a base64-encoded string to a vector of bytes.
pub fn decode_base64(b64: String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let b64_len = b64.len();
    let b64_cstr = CString::new(b64)?;
    let b64_ptr = b64_cstr.as_ptr() as *const i8;
    let mut bin = vec![0u8; b64_len];
    let mut bin_len: usize = 0;
    let ret = unsafe {
        sodium_base642bin(
            bin.as_mut_ptr(),
            bin.len(),
            b64_ptr,
            b64_len,
            ptr::null(),
            &mut bin_len,
            ptr::null_mut(),
            sodium_base64_VARIANT_ORIGINAL as c_int,
        )
    };
    if ret != 0 {
        return Err("Base64 decoding failed".into());
    }
    bin.truncate(bin_len);
    Ok(bin)
}