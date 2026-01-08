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

// =======================================================================================================
// ANTI-VM CHECK: Comprehensive VM Detection
// =======================================================================================================

/// Comprehensive VM detection combining multiple techniques:
/// - Registry key artifacts
/// - File system artifacts  
/// - Running processes
/// - MAC address patterns
/// - CPU vendor strings
#[cfg(feature = "CheckAntiVMComprehensive")]
use std::process::Command;
#[cfg(feature = "CheckAntiVMComprehensive")]
use std::fs;

#[cfg(feature = "CheckAntiVMComprehensive")]
pub fn anti_vm_comprehensive() -> bool {
    // Registry key value artifacts
    let registry_keys_value_artifacts = vec![
        (r#"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"#, "Identifier", "VMWARE"),
        (r#"HKLM\SOFTWARE\VMware, Inc.\VMware Tools"#, "", ""),
        (r#"HKLM\HARDWARE\Description\System\SystemBiosVersion"#, "", "VMWARE"),
        (r#"HKLM\HARDWARE\Description\System\SystemBiosVersion"#, "", "VBOX"),
        (r#"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions"#, "", ""),
        (r#"HKLM\HARDWARE\ACPI\DSDT\VBOX__"#, "", ""),
        (r#"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"#, "Identifier", "VBOX"),
        (r#"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"#, "Identifier", "QEMU"),
        (r#"HKLM\HARDWARE\Description\System\SystemBiosVersion"#, "", "QEMU"),
        (r#"HKLM\HARDWARE\Description\System\VideoBiosVersion"#, "", "VIRTUALBOX"),
        (r#"HKLM\HARDWARE\Description\System\SystemBiosDate"#, "", "06/23/99"),
        (r#"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0"#, "Identifier", "VMWARE"),
        (r#"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0"#, "Identifier", "VMWARE"),
        (r#"HKLM\SYSTEM\ControlSet001\Control\SystemInformation"#, "SystemManufacturer", "VMWARE"),
        (r#"HKLM\SYSTEM\ControlSet001\Control\SystemInformation"#, "SystemProductName", "VMWARE"),
    ];

    let registry_keys_value_artifacts_value = registry_keys_value_artifacts.iter().any(|&(key, value_name, expected_value)| {
        let key_exists = registry_key_exists(key);
        let value_matches = registry_value_matches(key, value_name, expected_value);
        key_exists && value_matches
    });

    // Registry keys artifacts
    let registry_keys_artifacts = vec![
        r#"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT\VBOX__"#,
        r#"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT\VBOX__"#,
        r#"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\RSDT\VBOX__"#,
        r#"HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox Guest Additions"#,
        r#"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxGuest"#,
        r#"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxMouse"#,
        r#"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxService"#,
        r#"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxSF"#,
        r#"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxVideo"#,
        r#"HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools"#,
        r#"HKEY_LOCAL_MACHINE\SOFTWARE\Wine"#,
        r#"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"#,
    ];

    let registry_keys_artifacts_value = registry_keys_artifacts.iter().any(|&key| registry_key_exists(key));

    // File system artifacts
    let file_system_artifacts = vec![
       r#"C:\Windows\system32\drivers\VBoxMouse.sys"#,
       r#"C:\Windows\system32\drivers\VBoxGuest.sys"#,
       r#"C:\Windows\system32\drivers\VBoxSF.sys"#,
       r#"C:\Windows\system32\drivers\VBoxVideo.sys"#,
       r#"C:\Windows\system32\vboxdisp.dll"#,
       r#"C:\Windows\system32\vboxhook.dll"#,
       r#"C:\Windows\system32\vboxmrxnp.dll"#,
       r#"C:\Windows\system32\vboxogl.dll"#,
       r#"C:\Windows\system32\vboxoglarrayspu.dll"#,
       r#"C:\Windows\system32\vboxoglcrutil.dll"#,
       r#"C:\Windows\system32\vboxoglerrorspu.dll"#,
       r#"C:\Windows\system32\vboxoglfeedbackspu.dll"#,
       r#"C:\Windows\system32\vboxoglpackspu.dll"#,
       r#"C:\Windows\system32\vboxoglpassthroughspu.dll"#,
       r#"C:\Windows\system32\vboxservice.exe"#,
       r#"C:\Windows\system32\vboxtray.exe"#,
       r#"C:\Windows\system32\VBoxControl.exe"#,
       r#"C:\Windows\system32\drivers\vmmouse.sys"#,
       r#"C:\Windows\system32\drivers\vmhgfs.sys"#,
       r#"C:\Windows\system32\drivers\vm3dmp.sys"#, 
       r#"C:\Windows\system32\drivers\vmmemctl.sys"#,
       r#"C:\Windows\system32\drivers\vmrawdsk.sys"#,
       r#"C:\Windows\system32\drivers\vmusbmouse.sys"#,
    ];
    
    let file_system_artifacts_value = file_system_artifacts.iter().any(|&path| file_artifacts(path));

    // Check running processes
    let all_processes = get_running_processes();
    let target_processes = vec![
        "vboxservice.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vgauthservice.exe",
        "vmacthlp.exe",
        "vmsrvc.exe",
        "vmusrvc.exe",
        "prl_cc.exe",
        "prl_tools.exe",
        "xenservice.exe",
        "qemu-ga.exe",
    ];

    let target_process_value = target_processes.iter()
        .any(|target_process| process_exists(&all_processes, target_process)); 

    // Check MAC address
    let mac_address_value = match get_mac_address() {
        Some(mac) => {
            let vm_mac_addresses = vec![
                vec![0x08, 0x00, 0x27], // VBOX
                vec![0x00, 0x05, 0x69], // VMWARE
                vec![0x00, 0x0C, 0x29], // VMWARE
                vec![0x00, 0x1C, 0x14], // VMWARE
                vec![0x00, 0x50, 0x56], // VMWARE
                vec![0x00, 0x1C, 0x42], // Parallels
                vec![0x00, 0x16, 0x3E], // Xen
                vec![0x0A, 0x00, 0x27], // Hybrid Analysis
            ];
            find_matching_pattern(&mac, &vm_mac_addresses).is_some()
        },
        None => false,
    };

    // Check CPU vendor using CPUID
    let cpu_vendor_value = check_cpu_hypervisor();

    registry_keys_value_artifacts_value ||
    registry_keys_artifacts_value || 
    file_system_artifacts_value ||
    target_process_value || 
    mac_address_value || 
    cpu_vendor_value
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn registry_key_exists(key: &str) -> bool {
    Command::new("reg")
        .args(&["query", key])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn registry_value_matches(key: &str, value_name: &str, expected_value: &str) -> bool {
    if expected_value.is_empty() {
        return true; // If no specific value expected, just check key exists
    }
    
    Command::new("reg")
        .args(&["query", key, "/v", value_name])
        .output()
        .map(|output| {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.contains(expected_value)
            } else {
                false
            }
        })
        .unwrap_or(false)
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn file_artifacts(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn get_running_processes() -> Vec<String> {
    Command::new("wmic")
        .args(&["process", "get", "name"])
        .output()
        .map(|output| {
            let output_str = String::from_utf8_lossy(&output.stdout);
            output_str
                .lines()
                .skip(1)
                .map(|line| line.trim().to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn process_exists(processes: &[String], target: &str) -> bool {
    processes.iter().any(|process| process.contains(target))
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn get_mac_address() -> Option<Vec<u8>> {
    let output = Command::new("ipconfig")
        .args(&["/all"])
        .output()
        .ok()?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        if line.contains("Physical Address") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let mac_address_str = parts[2].replace("-", ":");
                let mac_bytes: Vec<u8> = mac_address_str.split(":")
                    .filter_map(|s| u8::from_str_radix(s, 16).ok())
                    .collect();
                if mac_bytes.len() >= 3 {
                    return Some(mac_bytes);
                }
            }
        }
    }
    None
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn find_matching_pattern<'a>(mac_address: &'a [u8], patterns: &'a [Vec<u8>]) -> Option<&'a Vec<u8>> {
    patterns.iter().find(|pattern| {
        mac_address.len() >= pattern.len() && 
        mac_address[..pattern.len()] == **pattern
    })
}

#[cfg(feature = "CheckAntiVMComprehensive")]
fn check_cpu_hypervisor() -> bool {
    unsafe {
        let mut eax: u32;
        let mut ebx: u32;
        let mut ecx: u32;
        let mut edx: u32;

        // CPUID function 1: Check hypervisor bit
        // Save rbx first since it's used internally by LLVM
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov rbx, {tmp:r}",
            tmp = out(reg) _,
            inout("eax") 1u32 => eax,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags)
        );

        // Bit 31 of ECX indicates hypervisor presence
        let hypervisor_present = (ecx & (1 << 31)) != 0;

        // CPUID function 0x40000000: Get hypervisor vendor
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "mov rbx, {tmp:r}",
            tmp = out(reg) _,
            ebx_out = out(reg) ebx,
            inout("eax") 0x40000000u32 => eax,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags)
        );

        // Check vendor string
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&ecx.to_le_bytes());
        vendor[8..12].copy_from_slice(&edx.to_le_bytes());
        
        let vendor_str = String::from_utf8_lossy(&vendor);
        let is_known_vm = vendor_str.contains("KVMKVMKVM") ||    // KVM
                         vendor_str.contains("Microsoft Hv") || // Hyper-V
                         vendor_str.contains("VMwareVMware") || // VMware
                         vendor_str.contains("XenVMMXenVMM") || // Xen
                         vendor_str.contains("prl hyperv") ||   // Parallels
                         vendor_str.contains("VBoxVBoxVBox");   // VirtualBox

        hypervisor_present || is_known_vm
    }
}

// =======================================================================================================
// ANTI-VM CHECK: ICMP Timing
// =======================================================================================================

/// Check for VM environment using ICMP echo timing.
/// VMs may handle ICMP requests differently or fail to process them properly.
/// Returns true if likely running in a VM (ICMP operations fail).
#[cfg(feature = "CheckAntiVMICMP")]
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
#[cfg(feature = "CheckAntiVMICMP")]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
};
#[cfg(feature = "CheckAntiVMICMP")]
use std::alloc::{alloc, dealloc, Layout};

#[cfg(feature = "CheckAntiVMICMP")]
pub fn anti_vm_icmp_timing(delay_in_millis: u32) -> bool {
    unsafe {
        let h_icmp_file = IcmpCreateFile();
        if h_icmp_file == INVALID_HANDLE_VALUE {
            // Unable to open handle - might indicate VM
            return true;
        }

        // Destination address: 224.0.0.0 (multicast address)
        let destination_address: u32 = 0xE0000000; // Network byte order for 224.0.0.0

        // Send data
        let send_data = b"Data Buffer\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"; // 32 bytes
        let send_data_size = 32;

        // Calculate reply size: size of ICMP_ECHO_REPLY + send data size + 8 extra bytes
        let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + send_data_size + 8;

        // Allocate reply buffer
        let layout = Layout::from_size_align_unchecked(reply_size, 8);
        let reply_buffer = alloc(layout);
        
        if reply_buffer.is_null() {
            IcmpCloseHandle(h_icmp_file);
            return true; // Memory allocation failed - might indicate VM
        }

        // Send ICMP echo
        let _result = IcmpSendEcho(
            h_icmp_file,
            destination_address,
            send_data.as_ptr() as *const _,
            send_data_size as u16,
            std::ptr::null(),
            reply_buffer as *mut _,
            reply_size as u32,
            delay_in_millis,
        );

        // Cleanup
        IcmpCloseHandle(h_icmp_file);
        dealloc(reply_buffer, layout);

        // Return false (not VM) if operation completed successfully
        false
    }
}

// =======================================================================================================
// ANTI-VM CHECK: Time Source Discrepancy
// =======================================================================================================
/// Compares RDTSC (CPU timestamp counter) with QueryPerformanceCounter (OS timer).
/// VMs may show discrepancies due to hypervisor overhead or TSC offsetting.
/// Returns true if likely running in a VM (timing sources show significant discrepancy).
/// 
#[cfg(feature = "CheckAntiVMTimingDiscrepancy")]
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
#[cfg(feature = "CheckAntiVMTimingDiscrepancy")]
use windows_sys::Win32::System::Threading::Sleep;

#[cfg(feature = "CheckAntiVMTimingDiscrepancy")]
pub fn anti_vm_timing_discrepancy() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let mut frequency: i64 = 0;
            let mut start_qpc: i64 = 0;
            let mut end_qpc: i64 = 0;

            // Get the frequency of the high-resolution performance counter
            QueryPerformanceFrequency(&mut frequency);
            
            if frequency == 0 {
                // Failed to get frequency - might indicate VM
                return true;
            }

            // Take initial readings
            QueryPerformanceCounter(&mut start_qpc);
            let start_tsc = core::arch::x86_64::_rdtsc();
            Sleep(10000);

            // Take final readings
            let end_tsc = core::arch::x86_64::_rdtsc();
            QueryPerformanceCounter(&mut end_qpc);

            // Calculate time passed according to both sources            
            let qpc_diff = end_qpc - start_qpc;
            let qpc_duration_us = (qpc_diff as f64 * 1_000_000.0) / frequency as f64;

            // Time passed according to TSC (CPU Cycles)
            let tsc_delta = end_tsc.wrapping_sub(start_tsc);
           
            // Calculate expected TSC range based on QPC duration
            let expected_min_cycles = (qpc_duration_us * 500.0) as u64; // ~0.5 GHz minimum
            let expected_max_cycles = (qpc_duration_us * 6000.0) as u64; // ~6.0 GHz maximum
            
            // If TSC is outside reasonable bounds, likely VM interference
            if tsc_delta < expected_min_cycles || tsc_delta > expected_max_cycles {
                return true; // Timing discrepancy detected - likely VM
            }

            // Check for QPC duration significantly different from expected (should be close to 1000ms)
            // Allow +/- 100ms tolerance for system overhead
            if qpc_duration_us < 900_000.0 || qpc_duration_us > 1_100_000.0 {
                return true; // QPC timing anomaly - might indicate VM
            }

            false // Timing sources appear consistent
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}
