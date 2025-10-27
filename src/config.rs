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
    #[value(name = "createtimerqueuetimer")]
    CreateTimerQueueTimer,
    #[value(name = "enumuilanguages")]
    EnumUILanguages,
    #[value(name = "verifierenumerate")]
    VerifierEnumerate,
    #[value(name = "enumchildwindows")]
    EnumChildWindows,
    #[value(name = "enumdesktopwindows")]
    EnumDesktopWindows,
    #[value(name = "enumsystemlocales")]
    EnumSystemLocales,
    #[value(name = "certenumsystemstorelocation")]
    CertEnumSystemStoreLocation,
    #[value(name = "enumwindowstations")]
    EnumWindowStations,
    #[value(name = "enumdisplaymonitors")]
    EnumDisplayMonitors,
    #[value(name = "imagegetdigeststream")]
    ImageGetDigestStream,
    #[value(name = "certenumsystemstore")]
    CertEnumSystemStore,
    #[value(name = "enumtimeformats")]
    EnumTimeFormats,
    #[value(name = "cryptenumoidinfo")]
    CryptEnumOIDInfo,
    #[value(name = "immenuminputcontext")]
    ImmEnumInputContext,
}

impl ExecutionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            ExecutionMethod::Default => "ShellcodeExecuteDefault",
            ExecutionMethod::Fiber => "ShellcodeExecuteFiber",
            ExecutionMethod::CreateTimerQueueTimer => "ShellcodeExecuteCreateTimerQueueTimer",
            ExecutionMethod::EnumUILanguages => "ShellcodeExecuteEnumUILanguages",
            ExecutionMethod::VerifierEnumerate => "ShellcodeExecuteVerifierEnumerate",
            ExecutionMethod::EnumChildWindows => "ShellcodeExecuteEnumChildWindows",
            ExecutionMethod::EnumDesktopWindows => "ShellcodeExecuteEnumDesktopWindows",
            ExecutionMethod::EnumSystemLocales => "ShellcodeExecuteEnumSystemLocales",
            ExecutionMethod::CertEnumSystemStoreLocation => "ShellcodeExecuteCertEnumSystemStoreLocation",
            ExecutionMethod::EnumWindowStations => "ShellcodeExecuteEnumWindowStations",
            ExecutionMethod::EnumDisplayMonitors => "ShellcodeExecuteEnumDisplayMonitors",
            ExecutionMethod::ImageGetDigestStream => "ShellcodeExecuteImageGetDigestStream",
            ExecutionMethod::CertEnumSystemStore => "ShellcodeExecuteCertEnumSystemStore",
            ExecutionMethod::EnumTimeFormats => "ShellcodeExecuteEnumTimeFormats",
            ExecutionMethod::CryptEnumOIDInfo => "ShellcodeExecuteCryptEnumOIDInfo",
            ExecutionMethod::ImmEnumInputContext => "ShellcodeExecuteImmEnumInputContext",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ExecutionMethod::Default => "Default Execution (Syscalls)",
            ExecutionMethod::Fiber => "Fiber Execution",
            ExecutionMethod::CreateTimerQueueTimer => "CreateTimerQueueTimer Callback Execution",
            ExecutionMethod::EnumUILanguages => "EnumUILanguages Callback Execution",
            ExecutionMethod::VerifierEnumerate => "VerifierEnumerateResource Callback Execution",
            ExecutionMethod::EnumChildWindows => "EnumChildWindows Callback Execution",
            ExecutionMethod::EnumDesktopWindows => "EnumDesktopWindows Callback Execution",
            ExecutionMethod::EnumSystemLocales => "EnumSystemLocalesEx Callback Execution",
            ExecutionMethod::CertEnumSystemStoreLocation => "CertEnumSystemStoreLocation Callback Execution",
            ExecutionMethod::EnumWindowStations => "EnumWindowStationsW Callback Execution",
            ExecutionMethod::EnumDisplayMonitors => "EnumDisplayMonitors Callback Execution",
            ExecutionMethod::ImageGetDigestStream => "ImageGetDigestStream Callback Execution",
            ExecutionMethod::CertEnumSystemStore => "CertEnumSystemStore Callback Execution",
            ExecutionMethod::EnumTimeFormats => "EnumTimeFormatsEx Callback Execution",
            ExecutionMethod::CryptEnumOIDInfo => "CryptEnumOIDInfo Callback Execution",
            ExecutionMethod::ImmEnumInputContext => "ImmEnumInputContext Callback Execution",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InjectionMethod {
    #[value(name = "default")]
    Default,
}

impl InjectionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            InjectionMethod::Default => "InjectionDefaultLocal",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            InjectionMethod::Default => "Default Local Injection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EncryptionMethod {
    #[value(name = "tinyaes")]
    TinyAES,
    #[value(name = "ctaes")]
    CTAES,
}

impl EncryptionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            EncryptionMethod::TinyAES => "TinyAES",
            EncryptionMethod::CTAES => "CTAES",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            EncryptionMethod::TinyAES => "TinyAES Encryption",
            EncryptionMethod::CTAES => "CTAES Encryption",
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

    /// Shellcode injection method to use
    #[arg(long, value_enum, default_value = "default")]
    pub injection_method: InjectionMethod,

    /// Encryption method to use (optional)
    #[arg(long, value_enum)]
    pub encrypt: Option<EncryptionMethod>,

    /// Enable MessageBox feature in loader
    #[arg(long)]
    pub message_box: bool,

    /// Enable random calculation feature in loader
    #[arg(long)]
    pub random_calculation: bool,

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
