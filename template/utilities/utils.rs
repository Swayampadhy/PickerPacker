use std::ffi::c_void;

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
        
        // DON'T close the handle - keep it open until process exits
        // This ensures the deletion flag persists
        // CloseHandle(h_file);
        
        Ok(())
    }
}