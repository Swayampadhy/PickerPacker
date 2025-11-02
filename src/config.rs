// ============================================================================
// Configuration Module - CLI argument parsing and validation
// ============================================================================

use clap::Parser;
use crate::enums::*;

#[derive(Parser, Debug)]
#[command(
    name = "PickerPacker",
    author = "Swayam Tejas Padhy (@Leek0gg)",
    about = "A customizable payload packer",
    long_about = None,
    disable_version_flag = true
)]
pub struct PackerConfig {
    /// Input shellcode file to pack
    #[arg(short, long, required = true, value_name = "FILE")]
    pub input: String,

    /// Shellcode execution method to use
    #[arg(long, value_enum, default_value = "default")]
    pub execution: ExecutionMethod,

    /// Shellcode injection method to use
    #[arg(long, value_enum, default_value = "default")]
    pub injection: InjectionMethod,

    /// Check methods to enable (comma-separated or multiple --checks flags)
    #[arg(long, value_enum, value_delimiter = ',')]
    pub checks: Vec<CheckMethod>,

    /// Evasion methods to enable (comma-separated or multiple --evasion flags)
    #[arg(long, value_enum, value_delimiter = ',')]
    pub evasion: Vec<EvasionMethod>,

    /// Encryption method to use (optional)
    #[arg(long, value_enum)]
    pub encrypt: Option<EncryptionMethod>,

    /// AES encryption key (64 hex characters / 32 bytes)
    #[arg(
        long,
        value_name = "HEX",
        required_if_eq_any([("encrypt", "tinyaes"), ("encrypt", "ctaes")]),
        value_parser = validate_aes_key
    )]
    pub key: Option<String>,

    /// AES initialization vector (32 hex characters / 16 bytes)
    #[arg(
        long,
        value_name = "HEX",
        required_if_eq_any([("encrypt", "tinyaes"), ("encrypt", "ctaes")]),
        value_parser = validate_aes_iv
    )]
    pub iv: Option<String>,
}

impl PackerConfig {
    /// Create configuration from command-line arguments
    pub fn from_args() -> Self {
        PackerConfig::parse()
    }

    /// Get AES key as string
    pub fn aes_key(&self) -> String {
        self.key.clone().unwrap_or_default()
    }

    /// Get AES IV as string
    pub fn aes_iv(&self) -> String {
        self.iv.clone().unwrap_or_default()
    }
}

/// Validate AES key format
fn validate_aes_key(s: &str) -> Result<String, String> {
    if s.len() != 64 {
        return Err("AES key must be exactly 64 hex characters (32 bytes)".to_string());
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("AES key must contain only hexadecimal characters".to_string());
    }
    Ok(s.to_string())
}

/// Validate AES IV format
fn validate_aes_iv(s: &str) -> Result<String, String> {
    if s.len() != 32 {
        return Err("AES IV must be exactly 32 hex characters (16 bytes)".to_string());
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("AES IV must contain only hexadecimal characters".to_string());
    }
    Ok(s.to_string())
}