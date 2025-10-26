// ============================================================================
// Builder Module - Handles compilation and file operations
// ============================================================================

use std::env;
use std::fs::File;
use std::io::prelude::*;
use crate::config::PackerConfig;

pub fn build_compile_command(config: &PackerConfig) -> String {
    let mut compile_command = " build --release ".to_string();
    
    if config.do_message_box {
        compile_command.push_str("--features messagebox ");
    }
    if config.do_calculation {
        compile_command.push_str("--features calculation ");
    }
    if config.do_default_execution {
        compile_command.push_str("--features ShellcodeExecuteDefault ");
    }
    if config.do_tinyaes {
        compile_command.push_str("--features TinyAES ");
    }
    if config.embedded_payload {
        compile_command.push_str("--features embedded ");
    } else {
        compile_command.push_str("--features payloadFile ");
    }
    
    compile_command.push_str(" --manifest-path ./loader/Cargo.toml");
    
    // Detect OS and set appropriate compilation target
    #[cfg(target_os = "linux")]
    {
        println!("[*] Detected OS: Linux");
        println!("[*] Cross-compiling for Windows target: x86_64-pc-windows-gnu");
        compile_command.push_str(" --target x86_64-pc-windows-gnu");
    }
    
    #[cfg(target_os = "windows")]
    {
        println!("[*] Detected OS: Windows");
        println!("[*] Compiling for Windows target: x86_64-pc-windows-msvc");
        compile_command.push_str(" --target x86_64-pc-windows-msvc");
    }
    
    compile_command
}

pub fn setup_loader_directory() -> Result<(), std::io::Error> {
    std::fs::create_dir_all("loader")?;
    std::fs::create_dir_all("loader/src")?;
    Ok(())
}

pub fn copy_template_files(config: &PackerConfig) -> Result<(), std::io::Error> {
    // Copy execution module if default execution is enabled
    if config.do_default_execution {
        std::fs::copy("./template/execution.rs", "./loader/src/execution.rs")?;
    }
    
    // Copy AES-related files if TinyAES is enabled
    if config.do_tinyaes {
        std::fs::copy("./template/aes.rs", "./loader/src/aes.rs")?;
        std::fs::copy("./template/TinyAES.c", "./loader/TinyAES.c")?;
        std::fs::copy("./template/build.rs", "./loader/build.rs")?;
    }
    
    Ok(())
}

pub fn write_loader_stub(loader_stub: &str) -> Result<(), std::io::Error> {
    let mut file = File::create("./loader/src/main.rs")?;
    file.write_all(loader_stub.as_bytes())?;
    Ok(())
}

pub fn compile_loader(compile_command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path_to_cargo_project = env::current_dir()?;
    env::set_current_dir(&path_to_cargo_project)?;
    
    let output = std::process::Command::new("cargo")
        .env("CFLAGS", "-lrt")
        .env("LDFLAGS", "-lrt")
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .env("RUSTFLAGS", "-A warnings")
        .args(compile_command.split_whitespace())
        .output()?;

    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    
    if output.status.success() {
        Ok(())
    } else {
        println!("[-] Failed to compile!\r\n\r\n");
        let error_message = String::from_utf8_lossy(&output.stderr);
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            error_message.to_string()
        )))
    }
}
