// =======================================================================================================
// CHECKS WRAPPER
// =======================================================================================================

#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag", feature = "CheckAntiDebugProcessList", feature = "CheckAntiDebugHardwareBreakpoints"))]
use crate::checks::antidebug;

#[cfg(any(feature = "CheckAntiVMCPU", feature = "CheckAntiVMRAM", feature = "CheckAntiVMUSB", feature = "CheckAntiVMProcesses", feature = "CheckAntiVMHyperV"))]
use crate::checks::antivm;

#[cfg(feature = "CheckDomainJoined")]
use crate::checks::misc;

#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag", feature = "CheckAntiDebugProcessList", feature = "CheckAntiDebugHardwareBreakpoints", feature = "CheckAntiVMCPU", feature = "CheckAntiVMRAM", feature = "CheckAntiVMUSB", feature = "CheckAntiVMProcesses", feature = "CheckAntiVMHyperV", feature = "CheckDomainJoined"))]
use windows_sys::Win32::{
    Foundation::HWND,
    UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONINFORMATION},
};

/// Runs all enabled checks
#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag", feature = "CheckAntiDebugProcessList", feature = "CheckAntiDebugHardwareBreakpoints", feature = "CheckAntiVMCPU", feature = "CheckAntiVMRAM", feature = "CheckAntiVMUSB", feature = "CheckAntiVMProcesses", feature = "CheckAntiVMHyperV", feature = "CheckDomainJoined"))]
pub fn run_all_checks() -> bool {
    let mut debugging_detected = false;

    // ===================================================================
    // Anti-Debug Checks
    // ===================================================================
    
    #[cfg(feature = "CheckAntiDebugProcessDebugFlags")]
    {
        match antidebug::anti_dbg_nt_process_debug_flags() {
            Ok(debugger_detected) => {
                if debugger_detected {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                debugging_detected = true;
            }
        }
    }

    #[cfg(feature = "CheckAntiDebugSystemDebugControl")]
    {
        match antidebug::anti_dbg_nt_system_debug_control() {
            Ok(debugger_detected) => {
                if debugger_detected {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                debugging_detected = true;
            }
        }
    }

    #[cfg(feature = "CheckAntiDebugRemoteDebugger")]
    {
        match antidebug::anti_dbg_check_remote_debugger_present() {
            Ok(debugger_detected) => {
                if debugger_detected {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                debugging_detected = true;
            }
        }
    }

    #[cfg(feature = "CheckAntiDebugNtGlobalFlag")]
    {
        if antidebug::anti_dbg_nt_global_flag() {
            debugging_detected = true;
        }
    }

    #[cfg(feature = "CheckAntiDebugProcessList")]
    {
        if antidebug::anti_dbg_process_list() {
            debugging_detected = true;
        }
    }

    #[cfg(feature = "CheckAntiDebugHardwareBreakpoints")]
    {
        match antidebug::anti_dbg_hardware_breakpoints() {
            Ok(debugger_detected) => {
                if debugger_detected {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                debugging_detected = true;
            }
        }
    }

    // ===================================================================
    // Anti-VM Checks
    // ===================================================================
    
    #[cfg(feature = "CheckAntiVMCPU")]
    {
        if antivm::anti_vm_cpu() {
            debugging_detected = true;
        }
    }

    #[cfg(feature = "CheckAntiVMRAM")]
    {
        if antivm::anti_vm_ram() {
            debugging_detected = true;
        }
    }

    #[cfg(feature = "CheckAntiVMUSB")]
    {
        if antivm::anti_vm_usb() {
            debugging_detected = true;
        }
    }

    #[cfg(feature = "CheckAntiVMProcesses")]
    {
        if antivm::anti_vm_processes() {
            debugging_detected = true;
        }
    }

    #[cfg(feature = "CheckAntiVMHyperV")]
    {
        if antivm::anti_vm_hyperv() {
            debugging_detected = true;
        }
    }

    // ===================================================================
    // Miscellaneous Checks
    // ===================================================================
    
    #[cfg(feature = "CheckDomainJoined")]
    {
        if !misc::is_domain_joined() {
            debugging_detected = true;
        }
    }

    // If any check detected debugging, execute benign function
    if debugging_detected {
        execute_benign_function();
    }

    debugging_detected
}

/// Execute benign function to waste debugger's time
#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag", feature = "CheckAntiDebugProcessList", feature = "CheckAntiDebugHardwareBreakpoints", feature = "CheckAntiVMCPU", feature = "CheckAntiVMRAM", feature = "CheckAntiVMUSB", feature = "CheckAntiVMProcesses", feature = "CheckAntiVMHyperV", feature = "CheckDomainJoined"))]
fn execute_benign_function() {
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
