pub mod injection;
pub mod execution;

#[cfg(feature = "ShellcodeExecuteDefault")]
pub use execution::shellcode_execute_default;

#[cfg(feature = "ShellcodeExecuteFiber")]
pub use execution::shellcode_execute_fiber;

#[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
pub use execution::shellcode_execute_createtimerqueuetimer;

#[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
pub use execution::shellcode_execute_enumuilanguages;

#[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
pub use execution::shellcode_execute_verifierenumerate;

#[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
pub use execution::shellcode_execute_enumchildwindows;

#[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
pub use execution::shellcode_execute_enumdesktopwindows;

#[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
pub use execution::shellcode_execute_enumsystemlocales;

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
pub use execution::shellcode_execute_certenumsystemstorelocation;

#[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
pub use execution::shellcode_execute_enumwindowstations;

#[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
pub use execution::shellcode_execute_enumdisplaymonitors;

#[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
pub use execution::shellcode_execute_imagegetdigeststream;

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStore")]
pub use execution::shellcode_execute_certenumsystemstore;

#[cfg(feature = "ShellcodeExecuteEnumTimeFormats")]
pub use execution::shellcode_execute_enumtimeformats;

#[cfg(feature = "ShellcodeExecuteCryptEnumOIDInfo")]
pub use execution::shellcode_execute_cryptenumoidinfo;

#[cfg(feature = "ShellcodeExecuteImmEnumInputContext")]
pub use execution::shellcode_execute_immenuminputcontext;

#[cfg(feature = "ShellcodeExecuteEnumPropsW")]
pub use execution::shellcode_execute_enumpropsw;

#[cfg(feature = "ShellcodeExecuteEnumLanguageGroupLocalesW")]
pub use execution::shellcode_execute_enumlanguagegrouplocalesw;

#[cfg(feature = "ShellcodeExecuteSymEnumProcesses")]
pub use execution::shellcode_execute_symenumprocesses;

#[cfg(feature = "ShellcodeExecuteCopyFileExW")]
pub use execution::shellcode_execute_copyfileexw;

#[cfg(feature = "ShellcodeExecuteEnumObjects")]
pub use execution::shellcode_execute_enumobjects;

#[cfg(feature = "ShellcodeExecuteEnumResourceTypesW")]
pub use execution::shellcode_execute_enumresourcetypesw;
