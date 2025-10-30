use std::ffi::c_void;

// =======================================================================================================
// CHECKING FUNCTIONS WRAPPER
// =======================================================================================================

// Common imports for benign function (available if any check feature is enabled)
#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags"))]
use windows_sys::Win32::{
    Foundation::HWND,
    UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONINFORMATION},
};

/// Runs all enabled checks
#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags"))]
pub fn run_all_checks() -> bool {
    let mut debugging_detected = false;

    #[cfg(feature = "CheckAntiDebugProcessDebugFlags")]
    {
        match anti_dbg_nt_process_debug_flags() {
            Ok(is_safe) => {
                if !is_safe {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                // If check fails, assume debugging
                debugging_detected = true;
            }
        }
    }

    // Add more checks here as they are implemented

    // If any check detected debugging, execute benign function
    if debugging_detected {
        execute_benign_function();
    }

    debugging_detected
}

#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags"))]
fn execute_benign_function() {
    // Perform heavy calculations to waste debugger's time
    let mut result: u64 = 1;
    
    // Prime number calculations
    for i in 2..50000u64 {
        let mut is_prime = true;
        for j in 2..=(i as f64).sqrt() as u64 {
            if i % j == 0 {
                is_prime = false;
                break;
            }
        }
        if is_prime {
            result = result.wrapping_mul(i).wrapping_add(i);
        }
    }
    
    // Fibonacci sequence
    let mut fib_a: u64 = 0;
    let mut fib_b: u64 = 1;
    for _ in 0..10000 {
        let temp = fib_a.wrapping_add(fib_b);
        fib_a = fib_b;
        fib_b = temp;
        result = result.wrapping_add(fib_b);
    }
    
    // Matrix multiplication simulation
    for i in 0..1000 {
        for j in 0..1000 {
            result = result.wrapping_add((i * j) as u64);
        }
    }
    
    // Use result to prevent optimization
    let _ = result;
    
    // Show message box
    unsafe {
        let title: Vec<u16> = "Notice\0".encode_utf16().collect();
        let message: Vec<u16> = "Trial Ended\0".encode_utf16().collect();
        
        MessageBoxW(
            0 as HWND,
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

// =======================================================================================================
// =======================================================================================================
// ANTI-DEBUG CHECKS
// =======================================================================================================
// =======================================================================================================

// =======================================================================================================
// ANTI-DEBUG CHECK: NT Query Information Process - ProcessDebugFlags
// =======================================================================================================

#[cfg(feature = "CheckAntiDebugProcessDebugFlags")]
use windows_sys::Win32::{
    Foundation::{HANDLE, NTSTATUS},
    System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

#[cfg(feature = "CheckAntiDebugProcessDebugFlags")]
#[allow(non_camel_case_types)]
type fnNtQueryInformationProcess = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: i32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS;

#[cfg(feature = "CheckAntiDebugProcessDebugFlags")]
const ProcessDebugFlags: i32 = 0x1F;

#[cfg(feature = "CheckAntiDebugProcessDebugFlags")]
pub fn anti_dbg_nt_process_debug_flags() -> Result<bool, i32> {
    unsafe {
        let ntdll = GetModuleHandleA(b"NTDLL\0".as_ptr());
        if ntdll.is_null() {
            return Err(-1);
        }

        let nt_query_information_process_addr = GetProcAddress(
            ntdll,
            b"NtQueryInformationProcess\0".as_ptr(),
        );
        
        if nt_query_information_process_addr.is_none() {
            return Err(-2);
        }

        let nt_query_information_process: fnNtQueryInformationProcess =
            std::mem::transmute(nt_query_information_process_addr);

        let mut debug_flags = 0u32;
        let status = nt_query_information_process(
            -1isize as HANDLE, // Current process
            ProcessDebugFlags,
            &mut debug_flags as *mut u32 as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
        );

        if status != 0 {
            return Err(status);
        }

        Ok(debug_flags != 0)
    }
}

