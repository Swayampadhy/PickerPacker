use std::ffi::c_void;

// =======================================================================================================
// DYNAMIC API RESOLVER
// =======================================================================================================

use windows_sys::Win32::{
    Foundation::FARPROC,
    System::{
        Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS64},
        Kernel::LIST_ENTRY,
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
        Threading::{PEB, LDR_DATA_TABLE_ENTRY},
    },
};

#[inline]
#[cfg(target_pointer_width = "64")]
fn __readgsqword(offset: u32) -> u64 {
    let out: u64;
    unsafe {
        std::arch::asm!(
            "mov {}, gs:[{:e}]",
            lateout(reg) out,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
    }
    out
}

#[inline]
#[cfg(target_pointer_width = "32")]
fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    unsafe {
        std::arch::asm!(
            "mov {}, fs:[{:e}]",
            lateout(reg) out,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
    }
    out
}

pub fn get_module_base_addr(module_name: &str) -> *mut c_void {
    unsafe {
        #[cfg(target_pointer_width = "64")]
        let peb_offset: *const u64 = __readgsqword(0x60) as *const u64;
        
        #[cfg(target_pointer_width = "32")]
        let peb_offset: *const u32 = __readfsdword(0x30) as *const u32;
        
        let peb: PEB = *(peb_offset as *const PEB);

        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY =
            (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let buffer = std::slice::from_raw_parts(
                (*p_ldr_data_table_entry).FullDllName.Buffer.0,
                (*p_ldr_data_table_entry).FullDllName.Length as usize / 2,
            );
            let dll_name = String::from_utf16_lossy(buffer);

            if dll_name.to_lowercase().contains(&module_name.to_lowercase()) {
                let module_base = (*p_ldr_data_table_entry).Reserved2[0];
                return module_base;
            }
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                return std::ptr::null_mut();
            }
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

pub fn get_proc_addr(module_handle: *mut c_void, function_name: &str) -> FARPROC {
    unsafe {
        let dos_headers = module_handle as *const IMAGE_DOS_HEADER;
    
        let nt_headers =
            (module_handle as u64 + (*dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
    
        let data_directory =
            (&(*nt_headers).OptionalHeader.DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
    
        let export_directory = (module_handle as u64 + (*data_directory).VirtualAddress as u64)
            as *const IMAGE_EXPORT_DIRECTORY;
    
        let mut address_array =
            (module_handle as u64 + (*export_directory).AddressOfFunctions as u64) as u64;
    
        let mut name_array =
            (module_handle as u64 + (*export_directory).AddressOfNames as u64) as u64;
        let mut name_ordinals =
            (module_handle as u64 + (*export_directory).AddressOfNameOrdinals as u64) as u64;

        for _ in 0..(*export_directory).NumberOfNames {
            let name_offset: u32 = *(name_array as *const u32);
            let current_function_name =
                std::ffi::CStr::from_ptr((module_handle as u64 + name_offset as u64) as *const i8)
                    .to_str()
                    .unwrap_or("");

            if current_function_name == function_name {
                address_array = address_array
                    + (*(name_ordinals as *const u16) as u64 * (std::mem::size_of::<u32>() as u64));
                let fun_addr: FARPROC = std::mem::transmute(
                    module_handle as u64 + *(address_array as *const u32) as u64,
                );
                return fun_addr;
            }

            name_array = name_array + std::mem::size_of::<u32>() as u64;
            name_ordinals = name_ordinals + std::mem::size_of::<u16>() as u64;
        }
        
        None
    }
}

pub fn load_library_a(library_name: &str) -> *mut c_void {
    unsafe {
        let kernel32_base = get_module_base_addr("kernel32.dll");
        if kernel32_base.is_null() {
            return std::ptr::null_mut();
        }
        
        type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> *mut c_void;
        
        let load_library_addr = get_proc_addr(kernel32_base, "LoadLibraryA");
        if load_library_addr.is_none() {
            return std::ptr::null_mut();
        }
        
        let load_library_fn: LoadLibraryAFn = std::mem::transmute(load_library_addr);
        
        let lib_name_cstr = format!("{}\0", library_name);
        load_library_fn(lib_name_cstr.as_ptr())
    }
}

// =======================================================================================================
// UTILITY: SELF DELETION
// =======================================================================================================

#[cfg(feature = "UtilitySelfDeletion")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    Storage::FileSystem::{
        CreateFileW, FileDispositionInfo, FileRenameInfo, SetFileInformationByHandle,
        DELETE, FILE_SHARE_READ, OPEN_EXISTING, SYNCHRONIZE,
    },
    System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY},
};

#[cfg(feature = "UtilitySelfDeletion")]
#[repr(C)]
struct FILE_RENAME_INFO {
    flags: u32,
    root_directory: HANDLE,
    file_name_length: u32,
    file_name: [u16; 1], // Variable length array
}

#[cfg(feature = "UtilitySelfDeletion")]
#[repr(C)]
struct FILE_DISPOSITION_INFO {
    delete_file: u8,
}

#[cfg(feature = "UtilitySelfDeletion")]
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
        
        Ok(())
    }
}
