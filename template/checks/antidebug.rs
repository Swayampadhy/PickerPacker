// =======================================================================================================
// ANTI-DEBUG CHECKS
// Various techniques to detect if the process is being debugged
// =======================================================================================================

use std::ffi::c_void;

#[cfg(any(feature = "CheckAntiDebugProcessDebugFlags", feature = "CheckAntiDebugSystemDebugControl", feature = "CheckAntiDebugRemoteDebugger"))]
use windows_sys::Win32::{
    Foundation::{BOOL, HANDLE, NTSTATUS},
    System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Threading::GetCurrentProcess,
    },
};

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

        // ProcessDebugFlags returns 0 when debugger IS attached, non-zero when not attached
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

        // STATUS_DEBUGGER_INACTIVE (0xC0000354) = No debugger
        // STATUS_ACCESS_DENIED (0xC0000022) = No admin privileges
        // Return false (no debugger) for both INACTIVE and ACCESS_DENIED
        Ok(status != STATUS_DEBUGGER_INACTIVE && status != 0xC0000022u32 as i32)
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
// ANTI-DEBUG CHECK: NtGlobalFlag (PEB)
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
    
    let flags_mask = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;
    let masked_value = peb.NtGlobalFlag & flags_mask;
    
    // When debugged, ALL three heap flags should be set (0x70)
    // We check if the masked value equals the expected pattern
    masked_value == flags_mask
}

// =======================================================================================================
// ANTI-DEBUG CHECK: Process List
// =======================================================================================================

#[cfg(feature = "CheckAntiDebugProcessList")]
use sysinfo::System;

/// Checks for known debugger processes running on the system
#[cfg(feature = "CheckAntiDebugProcessList")]
pub fn anti_dbg_process_list() -> bool {
    let list = vec![
        "x64dbg",
        "x32dbg",
        "ida",
        "ida64",
        "idag",
        "idag64",
        "idaw",
        "idaw64",
        "idaq",
        "idaq64",
        "windbg",
        "ollydbg",
        "OllyDbg",
        "immunity debugger",
        "VsDebugConsole",
        "msvsmon",
        "devenv",
    ];

    let mut system = System::new_all();
    system.refresh_all();
    
    for (_, process) in system.processes() {
        // Convert OsStr to string and lowercase it
        if let Some(proc_name) = process.name().to_str() {
            let proc_name_lower = proc_name.to_lowercase();
            for name in &list {
                if proc_name_lower == name.to_lowercase() || proc_name_lower.contains(&name.to_lowercase()) {
                    return true; // Debugger detected
                }
            }
        }
    }
    
    false
}

// =======================================================================================================
// ANTI-DEBUG CHECK: Hardware Breakpoints
// =======================================================================================================

#[cfg(feature = "CheckAntiDebugHardwareBreakpoints")]
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};

#[cfg(feature = "CheckAntiDebugHardwareBreakpoints")]
use windows_sys::Win32::System::Threading::GetCurrentThread;

/// Checks hardware debug registers (Dr0, Dr1, Dr2, Dr3) for breakpoints.
/// 
/// This function retrieves the current thread's context using GetThreadContext
/// and inspects the debug registers to detect any hardware breakpoints.
#[cfg(feature = "CheckAntiDebugHardwareBreakpoints")]
pub fn anti_dbg_hardware_breakpoints() -> Result<bool, i32> {
    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        // CONTEXT_DEBUG_REGISTERS is 0x00000010 on x64
        ctx.ContextFlags = 0x00100010; // CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS

        let result = GetThreadContext(GetCurrentThread(), &mut ctx);
        
        if result == 0 {
            return Err(-1); // GetThreadContext failed
        }

        // Check if any debug register is set
        if ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 {
            return Ok(true); // Hardware breakpoint detected
        }

        Ok(false)
    }
}
