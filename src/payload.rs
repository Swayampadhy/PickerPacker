// ============================================================================
// Payload Processing Module
// ============================================================================

use crate::aes::{hex_to_bytes, aes_encrypt_payload, ctaes_encrypt_payload};
use crate::config::{PackerConfig, EncryptionMethod};

pub fn process_payload(data: Vec<u8>, config: &PackerConfig) -> Vec<u8> {
    match config.encrypt {
        Some(EncryptionMethod::TinyAES) => {
            let key_bytes = hex_to_bytes(&config.aes_key()).expect("Invalid key format");
            let iv_bytes = hex_to_bytes(&config.aes_iv()).expect("Invalid IV format");
            
            if key_bytes.len() != 32 {
                panic!("Key must be exactly 32 bytes");
            }
            if iv_bytes.len() != 16 {
                panic!("IV must be exactly 16 bytes");
            }
            
            match aes_encrypt_payload(&data, &key_bytes, &iv_bytes) {
                Some(encrypted) => {
                    println!("[+] Payload encrypted with TinyAES ({} bytes)", encrypted.len());
                    println!("[!] IMPORTANT: The final executable will require --key and --iv arguments:");
                    println!("    Usage: PickerPacker_Packed.exe --key {} --iv {}", config.aes_key(), config.aes_iv());
                    encrypted
                }
                None => panic!("Failed to encrypt payload"),
            }
        }
        Some(EncryptionMethod::CTAES) => {
            let key_bytes = hex_to_bytes(&config.aes_key()).expect("Invalid key format");
            let iv_bytes = hex_to_bytes(&config.aes_iv()).expect("Invalid IV format");
            
            if key_bytes.len() != 32 {
                panic!("Key must be exactly 32 bytes");
            }
            if iv_bytes.len() != 16 {
                panic!("IV must be exactly 16 bytes");
            }
            
            match ctaes_encrypt_payload(&data, &key_bytes, &iv_bytes) {
                Some(encrypted) => {
                    println!("[+] Payload encrypted with CTAES ({} bytes)", encrypted.len());
                    println!("[!] IMPORTANT: The final executable will require --key and --iv arguments:");
                    println!("    Usage: PickerPacker_Packed.exe --key {} --iv {}", config.aes_key(), config.aes_iv());
                    encrypted
                }
                None => panic!("Failed to encrypt payload"),
            }
        }
        None => data,
    }
}

pub fn embed_payload(loader_stub: &mut String, payload: &[u8], _config: &PackerConfig) {
    let placeholder = "const ENCPAYLOAD: &[u8] = &[];";
    let replacement = format!("const ENCPAYLOAD: &[u8] = &{:?};", payload);
    
    // More efficient single-pass replacement
    if let Some(pos) = loader_stub.find(placeholder) {
        loader_stub.replace_range(pos..pos + placeholder.len(), &replacement);
    }
}
