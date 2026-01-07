# PickerPacker Features

This document provides a comprehensive overview of all features available in PickerPacker.

---

## Table of Contents

- [Execution Methods](#execution-methods)
- [Injection Methods](#injection-methods)
- [Anti-Debug Checks](#anti-debug-checks)
- [Anti-VM Checks](#anti-vm-checks)
- [Evasion Techniques](#evasion-techniques)
- [Encryption Methods](#encryption-methods)
- [Miscellaneous Checks](#miscellaneous-checks)

---

## Execution Methods

Shellcode execution techniques that leverage various Windows API callbacks and execution primitives.

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **Default Execution** | `default` | Direct syscall-based shellcode execution |
| **Fiber Execution** | `fiber` | Execute shellcode via Windows Fiber API |
| **CreateTimerQueueTimer** | `createtimerqueuetimer` | Timer queue callback execution |
| **EnumUILanguages** | `enumuilanguages` | UI language enumeration callback |
| **VerifierEnumerate** | `verifierenumerate` | Application verifier enumeration callback |
| **EnumChildWindows** | `enumchildwindows` | Child window enumeration callback |
| **EnumDesktopWindows** | `enumdesktopwindows` | Desktop window enumeration callback |
| **EnumSystemLocales** | `enumsystemlocales` | System locale enumeration callback |
| **CertEnumSystemStoreLocation** | `certenumsystemstorelocation` | Certificate store location enumeration callback |
| **EnumWindowStations** | `enumwindowstations` | Window station enumeration callback |
| **EnumDisplayMonitors** | `enumdisplaymonitors` | Display monitor enumeration callback |
| **ImageGetDigestStream** | `imagegetdigeststream` | Image digest stream callback |
| **CertEnumSystemStore** | `certenumsystemstore` | Certificate system store enumeration callback |
| **EnumTimeFormats** | `enumtimeformats` | Time format enumeration callback |
| **CryptEnumOIDInfo** | `cryptenumoidinfo` | Cryptographic OID enumeration callback |
| **ImmEnumInputContext** | `immenuminputcontext` | Input method enumeration callback |
| **EnumPropsW** | `enumpropsw` | Window properties enumeration callback |
| **EnumLanguageGroupLocalesW** | `enumlanguagegrouplocalesw` | Language group locale enumeration callback |
| **SymEnumProcesses** | `symenumprocesses` | Symbol process enumeration callback |
| **CopyFileExW** | `copyfileexw` | File copy progress callback |
| **EnumObjects** | `enumobjects` | GDI object enumeration callback |
| **EnumResourceTypesW** | `enumresourcetypesw` | Resource type enumeration callback |
| **EnumPageFilesW** | `enumpagefilesw` | Page file enumeration callback |
| **EnumDirTreeW** | `enumdirtreew` | Directory tree enumeration callback |
| **EnumFontFamiliesW** | `enumfontfamiliesw` | Font family enumeration callback |
| **EnumDesktopsW** | `enumdesktopsw` | Desktop enumeration callback |
| **InitOnceExecuteOnce** | `initonceexecuteonce` | One-time initialization callback |
| **EnumThreadWindows** | `enumthreadwindows` | Thread window enumeration callback |
| **EnumerateLoadedModulesW64** | `enumerateloadedmodulesw64` | Loaded module enumeration callback |
| **EnumFontsW** | `enumfontsw` | Font enumeration callback |
| **EnumCalendarInfoW** | `enumcalendarinfow` | Calendar information enumeration callback |
| **EnumWindows** | `enumwindows` | Window enumeration callback |
| **EnumPwrSchemes** | `enumpwrschemes` | Power scheme enumeration callback |
| **SymFindFileInPath** | `symfindfileinpath` | Symbol file search callback |
| **FlsAlloc** | `flsalloc` | Fiber local storage callback |
| **WaitForMultipleObjectsEx APC** | `waitformultipleobjectsexapc` | APC-based execution via alertable multiple object wait state |
| **MsgWaitForMultipleObjectsEx APC** | `msgwaitformultipleobjectsexapc` | APC-based execution via message wait alertable state |
| **SleepEx APC** | `sleepexapc` | APC-based execution via SleepEx alertable state |
| **WaitForSingleObjectEx APC** | `waitforsingleobjectexapc` | APC-based execution via single object wait alertable state |
| **SignalObjectAndWait APC** | `signalobjectandwaitapc` | APC-based execution via signal and wait alertable state |
| **EnumSystemGeoID** | `enumsystemgeoid` | Geographic location enumeration callback |
| **ThreadpoolWait** | `threadpoolwait` | Threadpool wait callback execution (PTP_WAIT_CALLBACK) |
| **CDefFolderMenu_Create2** | `cdeffoldermenu` | Shell folder menu callback execution |

---

## Injection Methods

Techniques for injecting and executing shellcode in memory.

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **Default Local Injection** | `default` | Direct local process injection using syscalls |
| **Mapping Local Injection** | `mapping` | Memory mapping-based local injection |
| **Function Stomping** | `functionstomping` | Overwrite existing function with shellcode |
| **Module Stomping** | `modulestomping` | Overwrite module memory with shellcode |

---

## Anti-Debug Checks

Detection mechanisms to identify debuggers and debugging activity.

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **Process Debug Flags** | `dbgprocessdebugflags` | Check ProcessDebugFlags via NtQueryInformationProcess |
| **System Debug Control** | `dbgsystemdebugcontrol` | Check SystemKernelDebuggerInformation |
| **Remote Debugger** | `dbgremotedebugger` | Detect remote debugger via CheckRemoteDebuggerPresent |
| **NtGlobalFlag** | `dbgntglobalflag` | Check PEB NtGlobalFlag for debugger indicators |
| **Process List** | `dbgprocesslist` | Enumerate running processes for debugger names |
| **Hardware Breakpoints** | `dbghardwarebreakpoints` | Detect hardware breakpoints in debug registers |

---

## Anti-VM Checks

Virtual machine and sandbox detection techniques.

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **CPU Core Count** | `vmcpu` | Detect VM by checking if CPU cores < 2 |
| **RAM Size** | `vmram` | Detect VM by checking if RAM < 2GB |
| **USB History** | `vmusb` | Check registry for USB device history |
| **Process Count** | `vmprocesses` | Detect VM by low process count |
| **Hyper-V Detection** | `vmhyperv` | CPUID-based hypervisor detection |
| **Screen Resolution** | `vmresolution` | Detect VM by screen resolution < 1080x900 |
| **CPU Fan Detection** | `vmfan` | Query WMI for physical CPU fans (VMs lack these) |
| **Comprehensive VM Check** | `vmcomprehensive` | Multi-vector VM detection combining:<br>• Registry artifacts (VMware, VirtualBox, QEMU)<br>• File system artifacts (VM drivers/DLLs)<br>• Running VM processes (vmtoolsd, vboxservice)<br>• MAC address vendor prefixes<br>• CPUID hypervisor strings |


---

## Evasion Techniques

Security product bypass and evasion mechanisms.

### AMSI Evasion

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **AMSI Simple Patch** | `amsisimple` | Patch AmsiScanBuffer using syscalls |
| **AMSI Hardware Breakpoint** | `amsihwbp` | Use hardware breakpoint to bypass AMSI |
| **AMSI Page Guard Exception** | `amsipageguard` | Use page guard exceptions with VEH to bypass AMSI |

### ETW Evasion

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **ETW Simple Patch** | `etwsimple` | Patch NtTraceEvent using syscalls |
| **ETW WinAPI Patch** | `etwwinapi` | Patch EtwEventWrite and EtwEventWriteFull |
| **ETW Internal Patch** | `etwpeventwrite` | Patch internal EtwpEventWriteFull function |
| **ETW Call NOP** | `etwpeventwrite2` | NOP the CALL instruction to EtwpEventWriteFull |

### Other Evasion

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **NTDLL Unhooking** | `ntdllunhook` | Unhook NTDLL by restoring original bytes from disk |
| **Self Deletion** | `selfdelete` | Delete the executable from disk after execution |

**Note:** Only one AMSI method and one ETW method can be used together at a time.

---

## Encryption Methods

Shellcode encryption algorithms for obfuscation.

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **TinyAES** | `tinyaes` | Tiny AES implementation in C |
| **CTAES** | `ctaes` | Constant-time AES implementation |

**Requirements:**
- `--key <HEX>`: 64 hex characters (32 bytes) for AES key
- `--iv <HEX>`: 32 hex characters (16 bytes) for initialization vector

---

## Miscellaneous Checks

Additional environmental and security checks.

| Feature Name | CLI Flag | Description |
|-------------|----------|-------------|
| **Domain Joined Check** | `domainjoined` | Verify if system is joined to a domain |

---

## Feature Summary

| Category | Count | Description |
|----------|-------|-------------|
| **Execution Methods** | 43 | Shellcode execution techniques |
| **Injection Methods** | 4 | Memory injection methods |
| **Anti-Debug Checks** | 6 | Debugger detection |
| **Anti-VM Checks** | 8 | Virtual machine detection |
| **Evasion Techniques** | 9 | Security product bypass (3 AMSI + 4 ETW + 2 other) |
| **Encryption Methods** | 2 | Payload encryption |
| **Miscellaneous Checks** | 1 | Environmental checks |
| **TOTAL** | **73** | **Total features** |

---

## Usage Examples

### Basic Execution
```powershell
.\PickerPacker.exe --input shellcode.bin --execution fiber
```

### With Injection Method
```powershell
.\PickerPacker.exe --input shellcode.bin --execution enumwindows --injection modulestomping
```

### With Anti-Debug Checks
```powershell
.\PickerPacker.exe --input shellcode.bin --checks dbgprocesslist,vmcpu,vmram
```

### With Evasion Techniques
```powershell
.\PickerPacker.exe --input shellcode.bin --evasion amsisimple,etwwinapi,ntdllunhook
```

### With Encryption
```powershell
.\PickerPacker.exe --input shellcode.bin --encrypt tinyaes --key <64_hex_chars> --iv <32_hex_chars>
```

### Kitchen Sink (All Features)
```powershell
.\PickerPacker.exe --input shellcode.bin `
  --execution fiber `
  --injection modulestomping `
  --checks dbgprocesslist,vmcomprehensive,domainjoined `
  --evasion amsihwbp,etwpeventwrite2,ntdllunhook,selfdelete `
  --encrypt ctaes `
  --key <key> `
  --iv <iv>
```

---

## Feature Compatibility

### Compatible Combinations
- ✅ Any execution method + any injection method
- ✅ Multiple check methods together
- ✅ One AMSI method + one ETW method + other evasions
- ✅ Any encryption method with any other features

### Incompatible Combinations
- ❌ Multiple AMSI methods together (choose only one)
- ❌ Multiple ETW methods together (choose only one)

---

## Notes

- **Feature Flags:** All features are compiled as Cargo features for modularity
- **Syscalls:** Most evasion techniques use indirect syscalls via `rust_syscalls`
- **Windows API:** Execution and injection methods leverage Windows-sys bindings

---

**For contribution guidelines on adding new features, see [CONTRIBUTING.md](CONTRIBUTING.md)**

*Created by: Swayam Tejas Padhy (@Leek0gg)*  
*GitHub: https://github.com/Swayampadhy/PickerPacker*
