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
    #[value(name = "enumpropsw")]
    EnumPropsW,
    #[value(name = "enumlanguagegrouplocalesw")]
    EnumLanguageGroupLocalesW,
    #[value(name = "symenumprocesses")]
    SymEnumProcesses,
    #[value(name = "copyfileexw")]
    CopyFileExW,
    #[value(name = "enumobjects")]
    EnumObjects,
    #[value(name = "enumresourcetypesw")]
    EnumResourceTypesW,
    #[value(name = "enumpagefilesw")]
    EnumPageFilesW,
    #[value(name = "enumdirtreew")]
    EnumDirTreeW,
    #[value(name = "enumfontfamiliesw")]
    EnumFontFamiliesW,
    #[value(name = "enumdesktopsw")]
    EnumDesktopsW,
    #[value(name = "initonceexecuteonce")]
    InitOnceExecuteOnce,
    #[value(name = "enumthreadwindows")]
    EnumThreadWindows,
    #[value(name = "enumerateloadedmodulesw64")]
    EnumerateLoadedModulesW64,
    #[value(name = "enumfontsw")]
    EnumFontsW,
    #[value(name = "enumcalendarinfow")]
    EnumCalendarInfoW,
    #[value(name = "enumwindows")]
    EnumWindows,
    #[value(name = "enumpwrschemes")]
    EnumPwrSchemes,
    #[value(name = "symfindfileinpath")]
    SymFindFileInPath,
    #[value(name = "flsalloc")]
    FlsAlloc,
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
            ExecutionMethod::EnumPropsW => "ShellcodeExecuteEnumPropsW",
            ExecutionMethod::EnumLanguageGroupLocalesW => "ShellcodeExecuteEnumLanguageGroupLocalesW",
            ExecutionMethod::SymEnumProcesses => "ShellcodeExecuteSymEnumProcesses",
            ExecutionMethod::CopyFileExW => "ShellcodeExecuteCopyFileExW",
            ExecutionMethod::EnumObjects => "ShellcodeExecuteEnumObjects",
            ExecutionMethod::EnumResourceTypesW => "ShellcodeExecuteEnumResourceTypesW",
            ExecutionMethod::EnumPageFilesW => "ShellcodeExecuteEnumPageFilesW",
            ExecutionMethod::EnumDirTreeW => "ShellcodeExecuteEnumDirTreeW",
            ExecutionMethod::EnumFontFamiliesW => "ShellcodeExecuteEnumFontFamiliesW",
            ExecutionMethod::EnumDesktopsW => "ShellcodeExecuteEnumDesktopsW",
            ExecutionMethod::InitOnceExecuteOnce => "ShellcodeExecuteInitOnceExecuteOnce",
            ExecutionMethod::EnumThreadWindows => "ShellcodeExecuteEnumThreadWindows",
            ExecutionMethod::EnumerateLoadedModulesW64 => "ShellcodeExecuteEnumerateLoadedModulesW64",
            ExecutionMethod::EnumFontsW => "ShellcodeExecuteEnumFontsW",
            ExecutionMethod::EnumCalendarInfoW => "ShellcodeExecuteEnumCalendarInfoW",
            ExecutionMethod::EnumWindows => "ShellcodeExecuteEnumWindows",
            ExecutionMethod::EnumPwrSchemes => "ShellcodeExecuteEnumPwrSchemes",
            ExecutionMethod::SymFindFileInPath => "ShellcodeExecuteSymFindFileInPath",
            ExecutionMethod::FlsAlloc => "ShellcodeExecuteFlsAlloc",
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
            ExecutionMethod::EnumPropsW => "EnumPropsW Callback Execution",
            ExecutionMethod::EnumLanguageGroupLocalesW => "EnumLanguageGroupLocalesW Callback Execution",
            ExecutionMethod::SymEnumProcesses => "SymEnumProcesses Callback Execution",
            ExecutionMethod::CopyFileExW => "CopyFileExW Callback Execution",
            ExecutionMethod::EnumObjects => "EnumObjects Callback Execution",
            ExecutionMethod::EnumResourceTypesW => "EnumResourceTypesW Callback Execution",
            ExecutionMethod::EnumPageFilesW => "EnumPageFilesW Callback Execution",
            ExecutionMethod::EnumDirTreeW => "EnumDirTreeW Callback Execution",
            ExecutionMethod::EnumFontFamiliesW => "EnumFontFamiliesW Callback Execution",
            ExecutionMethod::EnumDesktopsW => "EnumDesktopsW Callback Execution",
            ExecutionMethod::InitOnceExecuteOnce => "InitOnceExecuteOnce Callback Execution",
            ExecutionMethod::EnumThreadWindows => "EnumThreadWindows Callback Execution",
            ExecutionMethod::EnumerateLoadedModulesW64 => "EnumerateLoadedModulesW64 Callback Execution",
            ExecutionMethod::EnumFontsW => "EnumFontsW Callback Execution",
            ExecutionMethod::EnumCalendarInfoW => "EnumCalendarInfoW Callback Execution",
            ExecutionMethod::EnumWindows => "EnumWindows Callback Execution",
            ExecutionMethod::EnumPwrSchemes => "EnumPwrSchemes Callback Execution",
            ExecutionMethod::SymFindFileInPath => "SymFindFileInPath Callback Execution",
            ExecutionMethod::FlsAlloc => "FlsAlloc Callback Execution",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InjectionMethod {
    #[value(name = "default")]
    Default,
    #[value(name = "mapping")]
    Mapping,
    #[value(name = "stomping")]
    FunctionStomping,
}

impl InjectionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            InjectionMethod::Default => "InjectionDefaultLocal",
            InjectionMethod::Mapping => "InjectionMappingLocal",
            InjectionMethod::FunctionStomping => "InjectionFunctionStomping",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            InjectionMethod::Default => "Default Local Injection",
            InjectionMethod::Mapping => "Mapping Local Injection",
            InjectionMethod::FunctionStomping => "Function Stomping Injection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UtilityMethod {
    #[value(name = "selfdelete")]
    SelfDelete,
}

impl UtilityMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            UtilityMethod::SelfDelete => "UtilitySelfDeletion",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            UtilityMethod::SelfDelete => "Self Deletion",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CheckMethod {
    #[value(name = "dbgprocessdebugflags")]
    AntiDebugProcessDebugFlags,
    #[value(name = "dbgsystemdebugcontrol")]
    AntiDebugSystemDebugControl,
    #[value(name = "dbgremotedebugger")]
    AntiDebugRemoteDebugger,
    #[value(name = "dbgntglobalflag")]
    AntiDebugNtGlobalFlag,
    #[value(name = "domainjoined")]
    DomainJoined,
}

impl CheckMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            CheckMethod::AntiDebugProcessDebugFlags => "CheckAntiDebugProcessDebugFlags",
            CheckMethod::AntiDebugSystemDebugControl => "CheckAntiDebugSystemDebugControl",
            CheckMethod::AntiDebugRemoteDebugger => "CheckAntiDebugRemoteDebugger",
            CheckMethod::AntiDebugNtGlobalFlag => "CheckAntiDebugNtGlobalFlag",
            CheckMethod::DomainJoined => "CheckDomainJoined",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            CheckMethod::AntiDebugProcessDebugFlags => "Anti-Debug: ProcessDebugFlags",
            CheckMethod::AntiDebugSystemDebugControl => "Anti-Debug: SystemDebugControl",
            CheckMethod::AntiDebugRemoteDebugger => "Anti-Debug: CheckRemoteDebuggerPresent",
            CheckMethod::AntiDebugNtGlobalFlag => "Anti-Debug: NtGlobalFlag (PEB)",
            CheckMethod::DomainJoined => "Environment Check: Domain Joined",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EvasionMethod {
    #[value(name = "amsisimple")]
    AMSISimplePatch,
    #[value(name = "etwsimple")]
    ETWSimple,
}

impl EvasionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            EvasionMethod::AMSISimplePatch => "EvasionAMSISimplePatch",
            EvasionMethod::ETWSimple => "EvasionETWSimple",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            EvasionMethod::AMSISimplePatch => "AMSI Evasion: Simple Patch",
            EvasionMethod::ETWSimple => "ETW Evasion: Simple Patch",
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
    pub execution_shellcode: ExecutionMethod,

    /// Shellcode injection method to use
    #[arg(long, value_enum, default_value = "default")]
    pub injection_method: InjectionMethod,

    /// Utility methods to enable (comma-separated or multiple --utils flags)
    #[arg(long, value_enum, value_delimiter = ',')]
    pub utils: Vec<UtilityMethod>,

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
