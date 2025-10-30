use std::ffi::c_void;

// =======================================================================================================
// COMMON IMPORTS FOR ALL CHECKS
// =======================================================================================================

// Common imports
#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag"))]
use windows_sys::Win32::{
    Foundation::{BOOL, HANDLE, HWND, NTSTATUS},
    System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Threading::GetCurrentProcess,
    },
    UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONINFORMATION},
};

// =======================================================================================================
// CHECKING FUNCTIONS WRAPPER
// =======================================================================================================

/// Runs all enabled checks
#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag"))]
pub fn run_all_checks() -> bool {
    let mut debugging_detected = false;

    #[cfg(feature = "CheckAntiDebugProcessDebugFlags")]
    {
        match anti_dbg_nt_process_debug_flags() {
            Ok(debugger_detected) => {
                if debugger_detected {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                // If check fails, assume debugging
                debugging_detected = true;
            }
        }
    }

    #[cfg(feature = "CheckAntiDebugSystemDebugControl")]
    {
        match anti_dbg_nt_system_debug_control() {
            Ok(debugger_detected) => {
                if debugger_detected {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                // If check fails, assume debugging
                debugging_detected = true;
            }
        }
    }

    #[cfg(feature = "CheckAntiDebugRemoteDebugger")]
    {
        match anti_dbg_check_remote_debugger_present() {
            Ok(debugger_detected) => {
                if debugger_detected {
                    debugging_detected = true;
                }
            }
            Err(_) => {
                // If check fails, assume debugging
                debugging_detected = true;
            }
        }
    }

    #[cfg(feature = "CheckAntiDebugNtGlobalFlag")]
    {
        if anti_dbg_nt_global_flag() {
            debugging_detected = true;
        }
    }

    // Add more checks here as they are implemented

    // If any check detected debugging, execute benign function
    if debugging_detected {
        execute_benign_function();
    }

    debugging_detected
}

#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger", feature = "CheckAntiDebugNtGlobalFlag"))]
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

        Ok(debug_flags == 0)
    }
}

// =======================================================================================================
// ANTI-DEBUG CHECK: NTSystemDebugControl (Admin Privileges Required)
// =======================================================================================================

#[cfg(feature = "CheckAntiDebugSystemDebugControl")]
const STATUS_DEBUGGER_INACTIVE: NTSTATUS = 0xC0000354u32 as i32;

#[cfg(feature = "CheckAntiDebugSystemDebugControl")]
#[allow(non_camel_case_types)]
type fnNtSystemDebugControl = unsafe extern "system" fn(
    command: SYSDBG_COMMAND,
    input_buffer: *mut c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
    return_length: *mut u32,
) -> NTSTATUS;

#[cfg(feature = "CheckAntiDebugSystemDebugControl")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum SYSDBG_COMMAND {
    SysDbgQueryModuleInformation = 0x0,
    SysDbgQueryTraceInformation = 0x1,
    SysDbgSetTracepoint = 0x2,
    SysDbgSetSpecialCall = 0x3,
    SysDbgClearSpecialCalls = 0x4,
    SysDbgQuerySpecialCalls = 0x5,
    SysDbgBreakPoint = 0x6,
    SysDbgQueryVersion = 0x7,
    SysDbgReadVirtual = 0x8,
    SysDbgWriteVirtual = 0x9,
    SysDbgReadPhysical = 0xA,
    SysDbgWritePhysical = 0xB,
    SysDbgReadControlSpace = 0xC,
    SysDbgWriteControlSpace = 0xD,
    SysDbgReadIoSpace = 0xE,
    SysDbgWriteIoSpace = 0xF,
    SysDbgReadMsr = 0x10,
    SysDbgWriteMsr = 0x11,
    SysDbgReadBusData = 0x12,
    SysDbgWriteBusData = 0x13,
    SysDbgCheckLowMemory = 0x14,
    SysDbgEnableKernelDebugger = 0x15,
    SysDbgDisableKernelDebugger = 0x16,
    SysDbgGetAutoKdEnable = 0x17,
    SysDbgSetAutoKdEnable = 0x18,
    SysDbgGetPrintBufferSize = 0x19,
    SysDbgSetPrintBufferSize = 0x1A,
    SysDbgGetKdUmExceptionEnable = 0x1B,
    SysDbgSetKdUmExceptionEnable = 0x1C,
    SysDbgGetTriageDump = 0x1D,
    SysDbgGetKdBlockEnable = 0x1E,
    SysDbgSetKdBlockEnable = 0x1F,
    SysDbgRegisterForUmBreakInfo = 0x20,
    SysDbgGetUmBreakPid = 0x21,
    SysDbgClearUmBreakPid = 0x22,
    SysDbgGetUmAttachPid = 0x23,
    SysDbgClearUmAttachPid = 0x24,
    SysDbgGetLiveKernelDump = 0x25,
    SysDbgKdPullRemoteFile = 0x26,
    SysDbgMaxInfoClass = 0x27,
}

#[cfg(feature = "CheckAntiDebugSystemDebugControl")]
pub fn anti_dbg_nt_system_debug_control() -> Result<bool, i32> {
    unsafe {
        let ntdll = GetModuleHandleA(b"NTDLL\0".as_ptr());
        if ntdll.is_null() {
            return Err(-1);
        }

        let nt_system_debug_control_addr = GetProcAddress(
            ntdll,
            b"NtSystemDebugControl\0".as_ptr(),
        );
        
        if nt_system_debug_control_addr.is_none() {
            return Err(-2);
        }

        let nt_system_debug_control: fnNtSystemDebugControl =
            std::mem::transmute(nt_system_debug_control_addr);

        let status = nt_system_debug_control(
            SYSDBG_COMMAND::SysDbgBreakPoint,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        // Returns true if debugging detected (status != STATUS_DEBUGGER_INACTIVE)
        Ok(status != STATUS_DEBUGGER_INACTIVE)
    }
}
// =======================================================================================================
// ANTI-DEBUG CHECK: CheckRemoteDebuggerPresent
// =======================================================================================================

#[cfg(feature = "CheckAntiDebugRemoteDebugger")]
#[allow(non_camel_case_types)]
type fnCheckRemoteDebuggerPresent = unsafe extern "system" fn(
    process: HANDLE,
    pb_debugger_present: *mut BOOL,
) -> BOOL;

#[cfg(feature = "CheckAntiDebugRemoteDebugger")]
pub fn anti_dbg_check_remote_debugger_present() -> Result<bool, i32> {
    unsafe {
        let kernel32 = GetModuleHandleA(b"KERNEL32.DLL\0".as_ptr());
        if kernel32.is_null() {
            return Err(-1);
        }

        let check_remote_debugger_addr = GetProcAddress(
            kernel32,
            b"CheckRemoteDebuggerPresent\0".as_ptr(),
        );
        
        if check_remote_debugger_addr.is_none() {
            return Err(-2);
        }

        let check_remote_debugger: fnCheckRemoteDebuggerPresent =
            std::mem::transmute(check_remote_debugger_addr);

        let mut debugger_present: BOOL = 0;
        let result = check_remote_debugger(
            GetCurrentProcess(),
            &mut debugger_present,
        );

        if result == 0 {
            // Function failed
            return Err(-3);
        }

        // Returns true if debugger is detected (debugger_present != 0)
        Ok(debugger_present != 0)
    }
}

// =======================================================================================================
// ANTI-DEBUG CHECK: NtGlobalFlag (PEB) (Admin Privileges Required)
// =======================================================================================================

#[cfg(feature = "CheckAntiDebugNtGlobalFlag")]
const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x10;
#[cfg(feature = "CheckAntiDebugNtGlobalFlag")]
const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x20;
#[cfg(feature = "CheckAntiDebugNtGlobalFlag")]
const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x40;

#[cfg(feature = "CheckAntiDebugNtGlobalFlag")]
pub fn anti_dbg_nt_global_flag() -> bool {
    let peb = super::peb::get_peb();
    
    // Returns true if debugger is detected
    peb.NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
}
