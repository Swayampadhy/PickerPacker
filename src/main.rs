// ============================================================================
// PickerPacker - Rust-Powered Customizable Packer
// Created by: Swayam Tejas Padhy (@Leek0gg)
// GitHub: https://github.com/Swayampadhy/PickerPacker
// ============================================================================

mod aes;
mod config;
mod utils;
mod payload;
mod builder;

use config::PackerConfig;
use utils::{print_banner, load_template, read_payload_file};
use payload::{process_payload, embed_payload};
use builder::{
    build_compile_command, setup_loader_directory, copy_template_files, 
    write_loader_stub, compile_loader, move_and_rename_executable,
    display_feature_summary
};

// ============================================================================
// Main Function
// ============================================================================

fn main() {
    print_banner();

    // Parse command-line arguments with clap
    let config = PackerConfig::from_args();
    
    // Display enabled features
    display_feature_summary(&config);

    let mut loader_stub = match load_template() {
        Ok(stub) => stub,
        Err(e) => {
            eprintln!("[-] Failed to load template: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] Reading payload from: {}", config.input);
    let payload_data = match read_payload_file(&config.input) {
        Ok(data) => {
            println!("[+] Payload read successfully ({} bytes)", data.len());
            data
        }
        Err(e) => {
            eprintln!("[-] Failed to read payload file: {}", e);
            std::process::exit(1);
        }
    };

    let (processed_payload, payload_type) = process_payload(payload_data, &config);

    // Validate that shellcode execution methods are only used for shellcode payloads
    use payload::PayloadType;
    use config::ExecutionMethod;
    
    match payload_type {
        PayloadType::PEExe | PayloadType::PEDll | PayloadType::CSharpAssembly => {
            let payload_type_name = match payload_type {
                PayloadType::PEExe => "PE Executable",
                PayloadType::PEDll => "PE DLL",
                PayloadType::CSharpAssembly => "C# Assembly",
                _ => "Unknown"
            };
            
            println!("[*] Detected payload type: {}", payload_type_name);
            
            // Check if a non-default execution method was specified
            if config.execution_shellcode != ExecutionMethod::Default {
                eprintln!("\n[-] ERROR: Shellcode execution method '{}' cannot be used with {} payloads!", 
                         config.execution_shellcode.display_name(), payload_type_name);
                std::process::exit(1);
            }
            
            println!("[*] PE/DLL/Assembly payloads will be embedded and executed directly");
        }
        PayloadType::Shellcode => {
            println!("[*] Detected payload type: Shellcode");
            println!("[*] Using execution method: {}", config.execution_shellcode.display_name());
        }
    }

    embed_payload(&mut loader_stub, &processed_payload, &config, &payload_type);

    let compile_command = build_compile_command(&config, &payload_type);

    if let Err(e) = setup_loader_directory() {
        eprintln!("[-] Failed to setup loader directory: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = copy_template_files(&config) {
        eprintln!("[-] Failed to copy template files: {}", e);
        std::process::exit(1);
    }

    println!("[*] Writing loader stub...");
    if let Err(e) = write_loader_stub(&loader_stub) {
        eprintln!("[-] Failed to write loader stub: {}", e);
        std::process::exit(1);
    }

    println!("[*] Compiling loader...");
    println!("[*] Compile command: cargo{}", compile_command);
    match compile_loader(&compile_command) {
        Ok(_) => {
            println!("[+] Compilation successful!");
            
            // Move and rename the executable
            println!("[*] Moving executable to root directory...");
            match move_and_rename_executable() {
                Ok(dest_path) => {
                    println!("[+] Packed executable created: {}", dest_path);
                    
                    if config.encrypt.is_some() {
                        println!("\n[!] Remember to run with: PickerPacker_Packed.exe --key {} --iv {}", 
                                 config.aes_key(), config.aes_iv());
                    }
                }
                Err(e) => {
                    eprintln!("[-] Failed to move executable: {}", e);
                    println!("[!] Original location:");
                    
                    #[cfg(target_os = "windows")]
                    println!("    .\\loader\\target\\x86_64-pc-windows-msvc\\release\\PickerPacker.exe");
                    
                    #[cfg(target_os = "linux")]
                    println!("    ./loader/target/x86_64-pc-windows-gnu/release/PickerPacker.exe");
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Compilation failed: {}", e);
            std::process::exit(1);
        }
    }
}
