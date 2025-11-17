// =======================================================================================================
// EXECUTION MODULE - Exports all shellcode execution methods
// =======================================================================================================

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

#[cfg(feature = "ShellcodeExecuteEnumPageFilesW")]
pub use execution::shellcode_execute_enumpagefilesw;

#[cfg(feature = "ShellcodeExecuteEnumDirTreeW")]
pub use execution::shellcode_execute_enumdirtreew;

#[cfg(feature = "ShellcodeExecuteEnumFontFamiliesW")]
pub use execution::shellcode_execute_enumfontfamiliesw;

#[cfg(feature = "ShellcodeExecuteEnumDesktopsW")]
pub use execution::shellcode_execute_enumdesktopsw;

#[cfg(feature = "ShellcodeExecuteInitOnceExecuteOnce")]
pub use execution::shellcode_execute_initonceexecuteonce;

#[cfg(feature = "ShellcodeExecuteEnumThreadWindows")]
pub use execution::shellcode_execute_enumthreadwindows;

#[cfg(feature = "ShellcodeExecuteEnumerateLoadedModulesW64")]
pub use execution::shellcode_execute_enumerateloadedmodulesw64;

#[cfg(feature = "ShellcodeExecuteEnumFontsW")]
pub use execution::shellcode_execute_enumfontsw;

#[cfg(feature = "ShellcodeExecuteEnumCalendarInfoW")]
pub use execution::shellcode_execute_enumcalendarinfow;

#[cfg(feature = "ShellcodeExecuteEnumWindows")]
pub use execution::shellcode_execute_enumwindows;

#[cfg(feature = "ShellcodeExecuteEnumPwrSchemes")]
pub use execution::shellcode_execute_enumpwrschemes;

#[cfg(feature = "ShellcodeExecuteSymFindFileInPath")]
pub use execution::shellcode_execute_symfindfileinpath;

#[cfg(feature = "ShellcodeExecuteFlsAlloc")]
pub use execution::shellcode_execute_flsalloc;

#[cfg(feature = "ShellcodeExecuteWaitForMultipleObjectsExAPC")]
pub use execution::shellcode_execute_waitformultipleobjectsexapc;

#[cfg(feature = "ShellcodeExecuteMsgWaitForMultipleObjectsExAPC")]
pub use execution::shellcode_execute_msgwaitformultipleobjectsexapc;

#[cfg(feature = "ShellcodeExecuteSleepExAPC")]
pub use execution::shellcode_execute_sleepexapc;

#[cfg(feature = "ShellcodeExecuteWaitForSingleObjectExAPC")]
pub use execution::shellcode_execute_waitforsingleobjectexapc;

#[cfg(feature = "ShellcodeExecuteSignalObjectAndWaitAPC")]
pub use execution::shellcode_execute_signalobjectandwaitapc;
