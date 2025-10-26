// ============================================================================
// Configuration Module
// ============================================================================

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExecutionMethod {
    #[value(name = "default")]
    Default,
    #[value(name = "fiber")]
    Fiber,
}

impl ExecutionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            ExecutionMethod::Default => "ShellcodeExecuteDefault",
            ExecutionMethod::Fiber => "ShellcodeExecuteFiber",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ExecutionMethod::Default => "Default Execution (Syscalls)",
            ExecutionMethod::Fiber => "Fiber Execution",
        }
    }
}

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

    /// Shellcode execution method to use
    #[arg(long, value_enum, default_value = "default")]
    pub execution_method: ExecutionMethod,

    /// Enable MessageBox feature in loader
    #[arg(long)]
    pub message_box: bool,

    /// Enable random calculation feature in loader
    #[arg(long)]
    pub random_calculation: bool,

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
