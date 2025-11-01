// ============================================================================
// Crypto Module - AES encryption/decryption helpers
// ============================================================================

#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
use crate::aes;

/// Convert hex string to bytes
#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    if !hex_str.len().is_multiple_of(2) {
        return Err("Hex string must have even length".to_string());
    }
    
    let mut bytes = Vec::new();
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i+2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => return Err(format!("Invalid hex characters: {}", byte_str)),
        }
    }
    Ok(bytes)
}

/// Decrypt payload using the appropriate AES method
#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
pub fn decrypt_payload(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    #[cfg(feature = "TinyAES")]
    {
        return aes::aes_decrypt(encrypted, key, iv);
    }
    
    #[cfg(feature = "CTAES")]
    {
        return aes::ctaes_decrypt(encrypted, key, iv);
    }
}
