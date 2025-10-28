// ============================================================================
// Payload Processing Module
// ============================================================================

use crate::aes::{hex_to_bytes, aes_encrypt_payload, ctaes_encrypt_payload};
use crate::config::{PackerConfig, EncryptionMethod};
use std::path::Path;

/// Check if a PE file is a .NET assembly by looking for the CLR/CLI header
fn is_dotnet_assembly(data: &[u8]) -> bool {
    if data.len() < 0x400 {
        return false;
    }
    
    // Check for MZ header
    if &data[0..2] != b"MZ" {
        return false;
    }
    
    // Get PE header offset (at 0x3C)
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    
    if data.len() < pe_offset + 0x18 + 0xE0 {
        return false;
    }
    
    // Verify PE signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return false;
    }
    
    // Check optional header magic to determine if it's PE32 or PE32+
    let optional_header_offset = pe_offset + 0x18;
    let magic = u16::from_le_bytes([data[optional_header_offset], data[optional_header_offset + 1]]);
    
    let cli_header_rva_offset = match magic {
        0x10b => optional_header_offset + 0xD0, // PE32
        0x20b => optional_header_offset + 0xE0, // PE32+
        _ => return false,
    };
    
    if data.len() < cli_header_rva_offset + 4 {
        return false;
    }
    
    // Check if CLR Runtime Header RVA is non-zero
    let cli_header_rva = u32::from_le_bytes([
        data[cli_header_rva_offset],
        data[cli_header_rva_offset + 1],
        data[cli_header_rva_offset + 2],
        data[cli_header_rva_offset + 3],
    ]);
    
    cli_header_rva != 0
}

pub enum PayloadType {
    Shellcode,
    PEExe,
    PEDll,
    CSharpAssembly,
}

/// Process the raw input and return (possibly encrypted) bytes plus the detected payload type
pub fn process_payload(data: Vec<u8>, config: &PackerConfig) -> (Vec<u8>, PayloadType) {
    // Detect payload type: check for PE header
    let payload_type = if data.len() >= 2 && &data[0..2] == b"MZ" {
        // It's a PE file - check if it's a .NET assembly by looking for the CLI header
        let is_dotnet = is_dotnet_assembly(&data);
        
        if is_dotnet {
            PayloadType::CSharpAssembly
        } else {
            // Regular native PE - decide exe vs dll by filename extension if available
            match Path::new(&config.input).extension().and_then(|s| s.to_str()) {
                Some(ext) if ext.eq_ignore_ascii_case("dll") => PayloadType::PEDll,
                _ => PayloadType::PEExe,
            }
        }
    } else {
        // fallback by extension: .dll/.exe
        match Path::new(&config.input).extension().and_then(|s| s.to_str()) {
            Some(ext) if ext.eq_ignore_ascii_case("dll") => PayloadType::PEDll,
            Some(ext) if ext.eq_ignore_ascii_case("exe") => PayloadType::PEExe,
            _ => PayloadType::Shellcode,
        }
    };
    let output = match config.encrypt {
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
    };

    (output, payload_type)
}
pub fn embed_payload(loader_stub: &mut String, payload: &[u8], _config: &PackerConfig, payload_type: &PayloadType) {
    let payload_placeholder = "const ENCPAYLOAD: &[u8] = &[];";
    let type_placeholder = "const ENCTYPE: &str = \"SHELLCODE\";";

    let replacement = format!("const ENCPAYLOAD: &[u8] = &{:?};", payload);
    let type_replacement = match payload_type {
        PayloadType::Shellcode => "const ENCTYPE: &str = \"SHELLCODE\";".to_string(),
        PayloadType::PEExe => "const ENCTYPE: &str = \"PE_EXE\";".to_string(),
        PayloadType::PEDll => "const ENCTYPE: &str = \"PE_DLL\";".to_string(),
        PayloadType::CSharpAssembly => "const ENCTYPE: &str = \"CSHARP_ASSEMBLY\";".to_string(),
    };

    // Replace payload bytes
    if let Some(pos) = loader_stub.find(payload_placeholder) {
        loader_stub.replace_range(pos..pos + payload_placeholder.len(), &replacement);
    }

    // Replace type placeholder (if exists). If not present, append after payload const
    if let Some(pos) = loader_stub.find(type_placeholder) {
        loader_stub.replace_range(pos..pos + type_placeholder.len(), &type_replacement);
    } else {
        // Try to insert near the payload const
        if let Some(pos) = loader_stub.find("const ENCPAYLOAD: &[u8]") {
            // find end of line
            if let Some(line_end) = loader_stub[pos..].find('\n') {
                let insert_pos = pos + line_end + 1;
                loader_stub.insert_str(insert_pos, &format!("\n{}\n", type_replacement));
            } else {
                loader_stub.push_str(&format!("\n{}\n", type_replacement));
            }
        } else {
            loader_stub.push_str(&format!("\n{}\n", type_replacement));
        }
    }
}
