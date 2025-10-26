// ============================================================================
// Configuration Module
// ============================================================================

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "PickerPacker",
    author = "Swayam Tejas Padhy (@Leek0gg)",
    version = "1.0",
    about = "A customizable payload packer",
    long_about = None
)]
pub struct PackerConfig {
    /// Input shellcode file to pack
    #[arg(short, long, required = true, value_name = "FILE")]
    pub input: String,

    /// Enable MessageBox feature in loader
    #[arg(long)]
    pub message_box: bool,

    /// Enable random calculation feature in loader
    #[arg(long)]
    pub random_calculation: bool,

    /// Enable default shellcode execution method
    #[arg(long)]
    pub default_execution: bool,

    /// Enable TinyAES encryption
    #[arg(long)]
    pub tinyaes: bool,

    /// Enable CTAES encryption
    #[arg(long)]
    pub ctaes: bool,

    /// AES encryption key (64 hex characters / 32 bytes)
    #[arg(
        long,
        value_name = "HEX",
        required_if_eq_any([("tinyaes", "true"), ("ctaes", "true")]),
        value_parser = validate_aes_key
    )]
    pub key: Option<String>,

    /// AES initialization vector (32 hex characters / 16 bytes)
    #[arg(
        long,
        value_name = "HEX",
        required_if_eq_any([("tinyaes", "true"), ("ctaes", "true")]),
        value_parser = validate_aes_iv
    )]
    pub iv: Option<String>,

    /// External shellcode file (disables embedding)
    #[arg(long, value_name = "FILE")]
    pub shellcode_file: Option<String>,
}

impl PackerConfig {
    /// Create configuration from command-line arguments
    pub fn from_args() -> Self {
        PackerConfig::parse()
    }

    /// Check if payload should be embedded
    pub fn embedded_payload(&self) -> bool {
        self.shellcode_file.is_none()
    }

    /// Check if default execution should be enabled
    pub fn should_use_default_execution(&self) -> bool {
        self.default_execution || !self.input.is_empty()
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
