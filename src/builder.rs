// ============================================================================
// Builder Module - Handles compilation and file operations
// ============================================================================

use std::env;
use std::fs::File;
use std::io::prelude::*;
use crate::config::PackerConfig;
// ============================================================================
// Template Module Registry
// ============================================================================

/// Represents a template module that can be included in the loader
#[derive(Debug)]
pub struct TemplateModule {
    pub name: &'static str,
    pub source_file: &'static str,
    pub dest_file: &'static str,
}

/// Registry of all available template modules
pub const TEMPLATE_MODULES: &[TemplateModule] = &[
    TemplateModule {
        name: "execution",
        source_file: "./template/execution.rs",
        dest_file: "./loader/src/execution.rs",
    },
    TemplateModule {
        name: "aes",
        source_file: "./template/aes.rs",
        dest_file: "./loader/src/aes.rs",
    },
];

/// Additional files that need to be copied for specific features
#[derive(Debug)]
pub struct AdditionalFile {
    pub feature: &'static str,
    pub source: &'static str,
    pub dest: &'static str,
}

pub const ADDITIONAL_FILES: &[AdditionalFile] = &[
    AdditionalFile {
        feature: "tinyaes",
        source: "./template/TinyAES.c",
        dest: "./loader/TinyAES.c",
    },
    AdditionalFile {
        feature: "tinyaes",
        source: "./template/build.rs",
        dest: "./loader/build.rs",
    },
    AdditionalFile {
        feature: "ctaes",
        source: "./template/CtAes.c",
        dest: "./loader/CtAes.c",
    },
    AdditionalFile {
        feature: "ctaes",
        source: "./template/build.rs",
        dest: "./loader/build.rs",
    },
];

pub fn build_compile_command(config: &PackerConfig) -> String {
    let mut compile_command = " build --release ".to_string();
    
    if config.message_box {
        compile_command.push_str("--features messagebox ");
    }
    if config.random_calculation {
        compile_command.push_str("--features calculation ");
    }
    if config.should_use_default_execution() {
        compile_command.push_str("--features ShellcodeExecuteDefault ");
    }
    if config.tinyaes {
        compile_command.push_str("--features TinyAES ");
    }
    if config.ctaes {
        compile_command.push_str("--features CTAES ");
    }
    if config.embedded_payload() {
        compile_command.push_str("--features embedded ");
    } else {
        compile_command.push_str("--features payloadFile ");
    }
    
    compile_command.push_str(" --manifest-path ./loader/Cargo.toml");
    
    // Detect OS and set appropriate compilation target
    #[cfg(target_os = "linux")]
    {
        compile_command.push_str(" --target x86_64-pc-windows-gnu");
    }
    
    #[cfg(target_os = "windows")]
    {
        compile_command.push_str(" --target x86_64-pc-windows-msvc");
    }
    
    compile_command
}

pub fn setup_loader_directory() -> Result<(), std::io::Error> {
    std::fs::create_dir_all("loader")?;
    std::fs::create_dir_all("loader/src")?;
    Ok(())
}

/// Copy a single template module file
fn copy_template_module(module: &TemplateModule) -> Result<(), std::io::Error> {
    std::fs::copy(module.source_file, module.dest_file)?;
    Ok(())
}

/// Check if a module should be included based on configuration
fn should_include_module(module_name: &str, config: &PackerConfig) -> bool {
    match module_name {
        "execution" => config.should_use_default_execution(),
        "aes" => config.tinyaes || config.ctaes,
        _ => false,
    }
}

/// Copy all required template modules based on enabled features
pub fn copy_template_files(config: &PackerConfig) -> Result<(), std::io::Error> {
    
    // Copy modules based on configuration
    for module in TEMPLATE_MODULES {
        if should_include_module(module.name, config) {
            copy_template_module(module)?;
        }
    }
    
    // Copy additional files (like C source, build scripts)
    for file in ADDITIONAL_FILES {
        if should_copy_additional_file(file.feature, config) {
            std::fs::copy(file.source, file.dest)?;
        }
    }
    
    Ok(())
}

/// Display summary of enabled features and modules
pub fn display_feature_summary(config: &PackerConfig) {
    println!("\n[*] ===== Feature Summary =====");
    
    let mut features = Vec::new();
    
    if config.message_box {
        features.push("MessageBox");
    }
    if config.random_calculation {
        features.push("Random Calculation");
    }
    if config.should_use_default_execution() {
        features.push("Default Execution (Syscalls)");
    }
    if config.tinyaes {
        features.push("TinyAES Encryption");
    }
    if config.ctaes {
        features.push("CTAES Encryption");
    }
    if config.embedded_payload() {
        features.push("Embedded Payload");
    } else {
        features.push("External Payload File");
    }
    
    if features.is_empty() {
        println!("[*] No additional features enabled");
    } else {
        for feature in features {
            println!("[+] {}", feature);
        }
    }
    
    println!("[*] ============================\n");
}

/// Check if additional files should be copied based on feature
fn should_copy_additional_file(feature: &str, config: &PackerConfig) -> bool {
    match feature {
        "tinyaes" => config.tinyaes,
        "ctaes" => config.ctaes,
        _ => false,
    }
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
    
    if output.status.success() {
        Ok(())
    } else {
        eprintln!("[-] Compilation failed!\n");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        let error_message = String::from_utf8_lossy(&output.stderr);
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            error_message.to_string()
        )))
    }
}

pub fn move_and_rename_executable() -> Result<String, std::io::Error> {
    // Determine the source path based on OS
    #[cfg(target_os = "windows")]
    let source_path = "./loader/target/x86_64-pc-windows-msvc/release/PickerPacker.exe";
    
    #[cfg(target_os = "linux")]
    let source_path = "./loader/target/x86_64-pc-windows-gnu/release/PickerPacker.exe";
    
    let dest_path = "./PickerPacker_Packed.exe";
    
    // Copy the file to the root directory with new name
    std::fs::copy(source_path, dest_path)?;
    
    Ok(dest_path.to_string())
}
