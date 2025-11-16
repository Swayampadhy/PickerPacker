// ============================================================================
// Enums Module - All feature enumerations with their trait implementations
// ============================================================================

use clap::ValueEnum;

// ============================================================================
// Execution Methods
// ============================================================================

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
    #[value(name = "waitformultipleobjectsexapc")]
    WaitForMultipleObjectsExAPC,
    #[value(name = "msgwaitformultipleobjectsexapc")]
    MsgWaitForMultipleObjectsExAPC,
    #[value(name = "sleepexapc")]
    SleepExAPC,
    #[value(name = "waitforsingleobjectexapc")]
    WaitForSingleObjectExAPC,
    #[value(name = "signalobjectandwaitapc")]
    SignalObjectAndWaitAPC,
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
            ExecutionMethod::WaitForMultipleObjectsExAPC => "ShellcodeExecuteWaitForMultipleObjectsExAPC",
            ExecutionMethod::MsgWaitForMultipleObjectsExAPC => "ShellcodeExecuteMsgWaitForMultipleObjectsExAPC",
            ExecutionMethod::SleepExAPC => "ShellcodeExecuteSleepExAPC",
            ExecutionMethod::WaitForSingleObjectExAPC => "ShellcodeExecuteWaitForSingleObjectExAPC",
            ExecutionMethod::SignalObjectAndWaitAPC => "ShellcodeExecuteSignalObjectAndWaitAPC",
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
            ExecutionMethod::WaitForMultipleObjectsExAPC => "WaitForMultipleObjectsEx APC Execution",
            ExecutionMethod::MsgWaitForMultipleObjectsExAPC => "MsgWaitForMultipleObjectsEx APC Execution",
            ExecutionMethod::SleepExAPC => "SleepEx APC Execution",
            ExecutionMethod::WaitForSingleObjectExAPC => "WaitForSingleObjectEx APC Execution",
            ExecutionMethod::SignalObjectAndWaitAPC => "SignalObjectAndWait APC Execution",
        }
    }
}

// ============================================================================
// Injection Methods
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InjectionMethod {
    #[value(name = "default")]
    Default,
    #[value(name = "mapping")]
    Mapping,
    #[value(name = "functionstomping")]
    FunctionStomping,
    #[value(name = "modulestomping")]
    ModuleStomping,
}

impl InjectionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            InjectionMethod::Default => "InjectionDefaultLocal",
            InjectionMethod::Mapping => "InjectionMappingLocal",
            InjectionMethod::FunctionStomping => "InjectionFunctionStomping",
            InjectionMethod::ModuleStomping => "InjectionModuleStomping",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            InjectionMethod::Default => "Default Local Injection",
            InjectionMethod::Mapping => "Mapping Local Injection",
            InjectionMethod::FunctionStomping => "Function Stomping Injection",
            InjectionMethod::ModuleStomping => "Module Stomping Injection",
        }
    }
}

// ============================================================================
// Check Methods
// ============================================================================

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
    #[value(name = "dbgprocesslist")]
    AntiDebugProcessList,
    #[value(name = "dbghardwarebreakpoints")]
    AntiDebugHardwareBreakpoints,
    #[value(name = "vmcpu")]
    AntiVMCPU,
    #[value(name = "vmram")]
    AntiVMRAM,
    #[value(name = "vmusb")]
    AntiVMUSB,
    #[value(name = "vmprocesses")]
    AntiVMProcesses,
    #[value(name = "vmhyperv")]
    AntiVMHyperV,
    #[value(name = "vmresolution")]
    AntiVMResolution,
    #[value(name = "vmfan")]
    AntiVMFan,
    #[value(name = "vmcomprehensive")]
    AntiVMComprehensive,
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
            CheckMethod::AntiDebugProcessList => "CheckAntiDebugProcessList",
            CheckMethod::AntiDebugHardwareBreakpoints => "CheckAntiDebugHardwareBreakpoints",
            CheckMethod::AntiVMCPU => "CheckAntiVMCPU",
            CheckMethod::AntiVMRAM => "CheckAntiVMRAM",
            CheckMethod::AntiVMUSB => "CheckAntiVMUSB",
            CheckMethod::AntiVMProcesses => "CheckAntiVMProcesses",
            CheckMethod::AntiVMHyperV => "CheckAntiVMHyperV",
            CheckMethod::AntiVMResolution => "CheckAntiVMResolution",
            CheckMethod::AntiVMFan => "CheckAntiVMFan",
            CheckMethod::AntiVMComprehensive => "CheckAntiVMComprehensive",
            CheckMethod::DomainJoined => "CheckDomainJoined",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            CheckMethod::AntiDebugProcessDebugFlags => "Anti-Debug: ProcessDebugFlags",
            CheckMethod::AntiDebugSystemDebugControl => "Anti-Debug: SystemDebugControl",
            CheckMethod::AntiDebugRemoteDebugger => "Anti-Debug: CheckRemoteDebuggerPresent",
            CheckMethod::AntiDebugNtGlobalFlag => "Anti-Debug: NtGlobalFlag (PEB)",
            CheckMethod::AntiDebugProcessList => "Anti-Debug: Debugger Process List",
            CheckMethod::AntiDebugHardwareBreakpoints => "Anti-Debug: Hardware Breakpoints",
            CheckMethod::AntiVMCPU => "Anti-VM: CPU Core Count",
            CheckMethod::AntiVMRAM => "Anti-VM: RAM Size",
            CheckMethod::AntiVMUSB => "Anti-VM: USB History",
            CheckMethod::AntiVMProcesses => "Anti-VM: Process Count",
            CheckMethod::AntiVMHyperV => "Anti-VM: Hyper-V Detection",
            CheckMethod::AntiVMResolution => "Anti-VM: Screen Resolution",
            CheckMethod::AntiVMFan => "Anti-VM: CPU Fan Detection",
            CheckMethod::AntiVMComprehensive => "Anti-VM: Comprehensive Detection",
            CheckMethod::DomainJoined => "Check: Domain Joined",
        }
    }
}

// ============================================================================
// Evasion Methods
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EvasionMethod {
    #[value(name = "amsisimple")]
    AMSISimplePatch,
    #[value(name = "amsihwbp")]
    AMSIHwbp,
    #[value(name = "etwsimple")]
    ETWSimple,
    #[value(name = "etwwinapi")]
    ETWWinAPI,
    #[value(name = "etwpeventwrite")]
    ETWpEventWrite,
    #[value(name = "etwpeventwrite2")]
    ETWpEventWrite2,
    #[value(name = "ntdllunhook")]
    NtdllUnhooking,
    #[value(name = "selfdelete")]
    SelfDeletion,
}

impl EvasionMethod {
    pub fn feature_name(&self) -> &'static str {
        match self {
            EvasionMethod::AMSISimplePatch => "EvasionAMSISimplePatch",
            EvasionMethod::AMSIHwbp => "EvasionAMSIHwbp",
            EvasionMethod::ETWSimple => "EvasionETWSimple",
            EvasionMethod::ETWWinAPI => "EvasionETWWinAPI",
            EvasionMethod::ETWpEventWrite => "EvasionETWpEventWrite",
            EvasionMethod::ETWpEventWrite2 => "EvasionETWpEventWrite2",
            EvasionMethod::NtdllUnhooking => "EvasionNtdllUnhooking",
            EvasionMethod::SelfDeletion => "EvasionSelfDeletion",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            EvasionMethod::AMSISimplePatch => "AMSI Evasion: Simple Patch",
            EvasionMethod::AMSIHwbp => "AMSI Evasion: Hardware Breakpoint",
            EvasionMethod::ETWSimple => "ETW Evasion: Simple Patch",
            EvasionMethod::ETWWinAPI => "ETW Evasion: WinAPI Event Write",
            EvasionMethod::ETWpEventWrite => "ETW Evasion: Internal EtwpEventWrite Patch",
            EvasionMethod::ETWpEventWrite2 => "ETW Evasion: NOP Call to EtwpEventWrite",
            EvasionMethod::NtdllUnhooking => "NTDLL Unhooking",
            EvasionMethod::SelfDeletion => "Self Deletion",
        }
    }
}

// ============================================================================
// Encryption Methods
// ============================================================================

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
