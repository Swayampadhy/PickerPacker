// =======================================================================================================
// PEB (Process Environment Block) STRUCTURES
// Structures for accessing PEB to perform anti-debug checks
// =======================================================================================================

#[repr(C)]
#[allow(non_snake_case, clippy::upper_case_acronyms)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub Spare: u8,
    pub Mutant: *const std::ffi::c_void,
    pub ImageBase: *mut std::ffi::c_void,
    pub LoaderData: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut windows_sys::Win32::System::Threading::RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *mut std::ffi::c_void,
    pub ProcessHeap: *mut std::ffi::c_void,
    pub FastPebLock: *mut std::ffi::c_void,
    pub FastPebLockRoutine: *mut std::ffi::c_void,
    pub FastPebUnlockRoutine: *mut std::ffi::c_void,
    pub EnvironmentUpdateCount: u32,
    pub KernelCallbackTable: *mut std::ffi::c_void,
    pub EventLogSection: *mut std::ffi::c_void,
    pub EventLog: *mut std::ffi::c_void,
    pub FreeList: *mut std::ffi::c_void,
    pub TlsExpansionCounter: u32,
    pub TlsBitmap: *mut std::ffi::c_void,
    pub TlsBitmapBits: [u32; 0x2],
    pub ReadOnlySharedMemoryBase: *mut std::ffi::c_void,
    pub ReadOnlySharedMemoryHeap: *mut std::ffi::c_void,
    pub ReadOnlyStaticServerData: *mut *mut std::ffi::c_void,
    pub AnsiCodePageData: *mut std::ffi::c_void,
    pub OemCodePageData: *mut std::ffi::c_void,
    pub UnicodeCaseTableData: *mut std::ffi::c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub Spare2: [u8; 0x4],
    pub CriticalSectionTimeout: u64,
    pub HeapSegmentReserve: u32,
    pub HeapSegmentCommit: u32,
    pub HeapDeCommitTotalFreeThreshold: u32,
    pub HeapDeCommitFreeBlockThreshold: u32,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: *mut *mut *mut std::ffi::c_void,
    pub GdiSharedHandleTable: *mut std::ffi::c_void,
    pub ProcessStarterHelper: *mut std::ffi::c_void,
    pub GdiDCAttributeList: *mut std::ffi::c_void,
    pub LoaderLock: *mut std::ffi::c_void,
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u32,
    pub OSPlatformId: u32,
    pub ImageSubSystem: u32,
    pub ImageSubSystemMajorVersion: u32,
    pub ImageSubSystemMinorVersion: u32,
    pub GdiHandleBuffer: [u32; 0x22],
    pub PostProcessInitRoutine: u32,
    pub TlsExpansionBitmap: u32,
    pub TlsExpansionBitmapBits: [u8; 0x80],
    pub SessionId: u32,
}
const _: () = assert!(
    std::mem::size_of::<PEB>() == 0x248,
    "PEB is incorrect size. Check compiler settings",
);

impl Default for PEB {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: usize,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: usize,
    pub ShutdownInProgress: u32,
    pub ShutdownThreadId: usize,
}
const _: () = assert!(
    std::mem::size_of::<PEB_LDR_DATA>() == 0x58,
    "PEB_LDR_DATA is incorrect size. Check compiler settings",
);

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: usize,
    pub EntryPoint: usize,
    pub SizeOfImage: u32,
    pub FullDllName: windows_sys::Win32::Foundation::UNICODE_STRING,
    pub BaseDllName: windows_sys::Win32::Foundation::UNICODE_STRING,
    pub Flags: u32,
    pub LoadCount: u16,
    pub TlsIndex: u16,
    pub Anon_0: LDR_DATA_TABLE_ENTRY_0,
    pub Anon_1: LDR_DATA_TABLE_ENTRY_1,
    pub EntryPointActivationContext: *mut std::ffi::c_void,
    pub PatchInformation: *mut std::ffi::c_void,
    pub ForwarderLinks: LIST_ENTRY,
    pub ServiceTagLinks: LIST_ENTRY,
    pub StaticLinks: LIST_ENTRY,
}

const _: () = assert!(
    std::mem::size_of::<LDR_DATA_TABLE_ENTRY>() == 0xC8,
    "PEB_LDR_DATA is incorrect size. Check compiler settings",
);

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
#[derive(Copy, Clone)]
pub struct LDR_DATA_TABLE_ENTRY_0_1 {
    SectionPointer: *mut std::ffi::c_void,
    CheckSum: u32,
}
const _: () = assert!(
    std::mem::size_of::<LDR_DATA_TABLE_ENTRY_0_1>() == 0x10,
    "PEB_LDR_DATA is incorrect size. Check compiler settings",
);

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    HashLinks: std::mem::ManuallyDrop<LIST_ENTRY>,
    Section: LDR_DATA_TABLE_ENTRY_0_1,
}
const _: () = assert!(
    std::mem::size_of::<LDR_DATA_TABLE_ENTRY_0>() == 0x10,
    "PEB_LDR_DATA is incorrect size. Check compiler settings",
);

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
pub union LDR_DATA_TABLE_ENTRY_1 {
    TimeDateStamp: u32,
    LoadedImports: *mut std::ffi::c_void,
}
const _: () = assert!(
    std::mem::size_of::<LDR_DATA_TABLE_ENTRY_1>() == 0x8,
    "PEB_LDR_DATA is incorrect size. Check compiler settings",
);

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}
const _: () = assert!(
    std::mem::size_of::<LIST_ENTRY>() == 0x10,
    "LIST_ENTRY is incorrect size. Check compiler settings",
);
impl Default for LIST_ENTRY {
    fn default() -> Self {
        Self {
            Flink: std::ptr::null_mut(),
            Blink: std::ptr::null_mut(),
        }
    }
}

#[inline]
pub fn get_peb() -> &'static PEB {
    #[cfg(all(windows, target_arch = "x86_64"))]
    unsafe {
        std::mem::transmute(__readgsqword(0x60))
    }

    #[cfg(all(windows, target_arch = "x86"))]
    unsafe {
        std::mem::transmute(__readfsdword(0x30))
    }
}

#[inline]
pub fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm! {
        "mov {:r}, gs:[{:r}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
        }
    };
    out
}

#[inline]
pub fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    unsafe {
        core::arch::asm! {
        "mov {:e}, fs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
        }
    };
    out
}
