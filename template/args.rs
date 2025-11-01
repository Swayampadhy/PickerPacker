// ============================================================================
// Arguments Module - Parse and validate runtime arguments
// ============================================================================

#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
use std::env;
#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
use crate::crypto::hex_to_bytes;

/// Parse and validate AES arguments from command line
/// Returns (key_bytes, iv_bytes) if valid, otherwise exits with error
#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
pub fn parse_and_validate_aes_args() -> (Vec<u8>, Vec<u8>) {
    let args: Vec<String> = env::args().collect();
    let mut aes_key_str = String::new();
    let mut aes_iv_str = String::new();
    
    // Parse command-line arguments
    for i in 0..args.len() {
        match args[i].as_str() {
            "--key" if i < args.len() - 1 => aes_key_str = args[i + 1].clone(),
            "--iv" if i < args.len() - 1 => aes_iv_str = args[i + 1].clone(),
            _ => {}
        }
    }
    
    // Check if key and IV are provided
    if aes_key_str.is_empty() || aes_iv_str.is_empty() {
        eprintln!("[-] Error: AES decryption requires both --key and --iv arguments");
        eprintln!("    Usage: PickerPacker.exe --key <64_hex_chars> --iv <32_hex_chars>");
        std::process::exit(1);
    }
    
    // Validate and convert key (must be 32 bytes = 64 hex chars)
    let aes_key = match hex_to_bytes(&aes_key_str) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(_) => {
            eprintln!("[-] Error: AES key must be exactly 32 bytes (64 hex characters)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[-] Error parsing AES key: {}", e);
            std::process::exit(1);
        }
    };
    
    // Validate and convert IV (must be 16 bytes = 32 hex chars)
    let aes_iv = match hex_to_bytes(&aes_iv_str) {
        Ok(bytes) if bytes.len() == 16 => bytes,
        Ok(_) => {
            eprintln!("[-] Error: AES IV must be exactly 16 bytes (32 hex characters)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[-] Error parsing AES IV: {}", e);
            std::process::exit(1);
        }
    };
    
    (aes_key, aes_iv)
}
