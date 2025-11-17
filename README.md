# PickerPacker

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows) ![Linux](https://img.shields.io/badge/Linux-FCC624)
[![Release](https://img.shields.io/badge/Release-v1.1-green.svg)](https://github.com/Swayampadhy/PickerPacker/releases)

**A modular and customizable shellcode packer written in Rust** that provides operators with granular control over execution, evasion, and obfuscation techniques.

PickerPacker allows you to mix and match 64+ different features to create custom attack chains tailored to your specific needs. From stealthy callback-based execution to comprehensive VM detection and multi-layer evasion, PickerPacker gives you the flexibility to bypass modern security controls. 

---

##  Key Features
- **40 execution techniques** including WinAPI callbacks, Fiber execution, APC execution and many more...
- Injection Methods such as memory mapping and function/module stomping.
- Multiple Anti-VM and Anti-Debug checks.
- Multiple AMSI and ETW bypasses and other evasion techniques.
- Payload encryption using TinyAES and CTAES.

##### Additional Features
- Compile-time payload embedding
- Modular Cargo feature system - enable only what you need
- Indirect syscalls via rust_syscalls
- Benign thread simulation customization
---

## 📊 Feature Statistics

| Category | Count | Description |
|----------|-------|-------------|
| **Execution Methods** | 40 | Callback-based and alternative execution primitives |
| **Injection Methods** | 4 | Memory injection and stomping techniques |
| **Anti-Debug** | 6 | Debugger detection mechanisms |
| **Anti-VM** | 8 | Virtual machine and sandbox detection |
| **Evasion** | 8 | AMSI, ETW, and unhooking techniques |
| **Encryption** | 2 | AES encryption variants |
| **Other Checks** | 1 | Domain joined verification |
| **TOTAL** | **69** | **Complete feature set** |

For detailed documentation of all features, see **[FEATURES.md](FEATURES.md)**

**Want to contribute?** Check out  [CONTRIBUTING.md](CONTRIBUTING.md) to add these features or propose new ones!

---

## Payload Support
**PickerPacker currently supports shellcode payloads only.** Multi-payload support (PE, DLL, .NET) is planned for future releases.

To use other payload types, convert them to shellcode first:
- **[Donut](https://github.com/TheWover/donut)** - For .NET assemblies and DLLs
- **[pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)** - For PE files
- **[sRDI](https://github.com/monoxgas/sRDI)** - For native DLLs


**You can customize the benign behavior of the packer by modifying `template/benign.rs`. See inline comments in that file for instructions.**

---

## Quick Start

#### Prerequisites
- **Rust 1.70+** ([Install Rust](https://www.rust-lang.org/tools/install))
- **Windows 10/11** (x64)
- **Visual Studio Build Tools** or equivalent (for linking) 
    - **Linux** - `rustup target add x86_64-pc-windows-msvc` for linux
    - **Windows** - [MSVC Build Tools](https://aka.ms/vs/17/release/vs_BuildTools.exe)
### Installation

#### From Source
```powershell
# Clone the repository
git clone https://github.com/Swayampadhy/PickerPacker.git
cd PickerPacker

# Build the packer
cargo build --release      # The binary will be at: .\target\release\PickerPacker.exe
```

#### From Releases
```powershell
# Download And Extract The Latest Release
cd PickerPacker

# Run The Packer Binary
./PickerPacker.exe
```

---

## Usage

### Basic Command Structure

```powershell
.\PickerPacker.exe --input <shellcode_file> [OPTIONS]
```

### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--input <FILE>` | **Required.** Path to shellcode file | `--input calc.bin` |
| `--execution <METHOD>` | Execution technique (default: `default`) | `--execution fiber` |
| `--injection <METHOD>` | Injection method (default: `default`) | `--injection modulestomping` |
| `--checks <CHECKS>` | Comma-separated check methods | `--checks dbgprocesslist,vmcpu` |
| `--evasion <EVASION>` | Comma-separated evasion techniques | `--evasion amsisimple,etwwinapi` |
| `--encrypt <METHOD>` | Encryption algorithm (`tinyaes` or `ctaes`) | `--encrypt tinyaes` |
| `--key <HEX>` | AES key (64 hex chars / 32 bytes) | `--key ABC123...` |
| `--iv <HEX>` | AES IV (32 hex chars / 16 bytes) | `--iv DEF456...` |

### Usage Examples

#### 1️⃣ Basic Execution
```powershell
.\PickerPacker.exe --input shellcode.bin
```

#### 2️⃣ With Execution Method
```powershell
.\PickerPacker.exe --input shellcode.bin --execution fiber
```

#### 3️⃣ With Injection Method
```powershell
.\PickerPacker.exe --input shellcode.bin --execution enumwindows --injection modulestomping
```

#### 4️⃣ With Anti-Debug Checks
```powershell
.\PickerPacker.exe --input shellcode.bin --checks dbgprocesslist,vmcpu,vmram
```

#### 5️⃣ With Evasion Techniques
```powershell
.\PickerPacker.exe --input shellcode.bin --evasion amsisimple,etwwinapi,ntdllunhook
```

#### 6️⃣ With Encryption
```powershell
# Generate random key and IV (PowerShell)
$key = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$iv = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })

# Pack with encryption
.\PickerPacker.exe --input shellcode.bin --encrypt tinyaes --key $key --iv $iv
```

#### 7️⃣ Kitchen Sink (All Features)
```powershell
.\PickerPacker.exe --input shellcode.bin `
  --execution fiber `
  --injection modulestomping `
  --checks dbgprocesslist,vmcomprehensive,domainjoined `
  --evasion amsihwbp,etwpeventwrite2,ntdllunhook,selfdelete `
  --encrypt ctaes `
  --key <your_64_hex_key> `
  --iv <your_32_hex_iv>
```

### Running the Packed Executable

```powershell
# If Compiled Without Encryption
.\PickerPacker_Packed.exe      # No additional arguments needed 

# If Compiled With Encryption
.\PickerPacker_Packed.exe --key <key value> --iv <iv value>
```

---

## Feature Compatibility

#### ✅ Valid Combinations
- Any execution method + any injection method
- Multiple check methods together
- **One AMSI method + one ETW method** + other evasions
- Any encryption method with other features

#### ❌ Invalid Combinations
- **Multiple AMSI methods** together (choose only one: `amsisimple` OR `amsihwbp`)
- **Multiple ETW methods** together (choose only one: `etwsimple` OR `etwwinapi` OR `etwpeventwrite` OR `etwpeventwrite2`)

**Example Valid Evasion:**
```powershell
--evasion amsisimple,etwwinapi,ntdllunhook,selfdelete  # ✅ OK (1 AMSI + 1 ETW + others)
```

**Example Invalid Evasion:**
```powershell
--evasion amsisimple,amsihwbp,etwsimple  # ❌ ERROR (2 AMSI methods)
```

---

## Sample Output

```powershell
PS E:\Projects\PickerPacker> PickerPacker.exe --input shellcode.bin
--encrypt ctaes --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--iv 0123456789abcdef0123456789abcdef --execution enumdesktopwindows
--injection functionstomping --evasion etwsimple,amsisimple,
ntdllunhook --checks dbgprocessdebugflags,dbgsystemdebugcontrol,
dbgremotedebugger,dbgntglobalflag,dbgprocesslist,dbghardwarebreakpoints     
                  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      ⠀⢀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀     ⢀⣠⡶⠿⠿⠿⠭⢤⣀⣀⠉⣩⡟⠒⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀     ⣠⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    ⠀ ⢰⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀     ⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀     ⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⣀⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⠀⠀⠀⠀⢀⣤⠤⠤⠤⢤⣀⠀⠀
   ⢰⠋⠀⠀⠀⠉⠙⠲⢤⣀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡄⢀⡴⠚⠉⠀⠀⠀⠀⠀⠈⢳⡄
   ⢸⡄⠀⠀⠀⠀⠀⠀⠀⠈⠑⢦⣧⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⡴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡷
   ⠈⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⢭⣉⠙⠛⠒⠲⠶⠶⠶⠶⠖⠒⠒⠒⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠃
⠀    ⠀⠙⢶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠲⢤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠃⠀
    ⠀⠀⠀⠀⠈⠙⠢⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠦⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠋⠀⠀⠀
⠀    ⠀⠀⠀⠀⠀⠀⠀⠈⠉⠓⠒⠒⠂⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⣤⣤⠤⠤⠤⠤⠤⠤⠒⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

           ██████╗ ██╗ ██████╗██╗  ██╗███████╗██████╗ 
           ██╔══██╗██║██╔════╝██║ ██╔╝██╔════╝██╔══██╗
           ██████╔╝██║██║     █████╔╝ █████╗  ██████╔╝
           ██╔═══╝ ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
           ██║     ██║╚██████╗██║  ██╗███████╗██║  ██║
           ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
             ██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
             ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
             ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
             ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
             ██║     ██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
             ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    
        ✧･ﾟ:*✧･ﾟ:* Rust-Powered Customizable Packer *:･ﾟ✧*:･ﾟ✧
    
        Created by: Swayam Tejas Padhy (@Leek0gg)
        GitHub: https://github.com/Swayampadhy/PickerPacker

    

[*] ============================
[*] FEATURES ENABLED:
[*] ============================
[+] Anti-Debug: ProcessDebugFlags
[+] Anti-Debug: SystemDebugControl
[+] Anti-Debug: CheckRemoteDebuggerPresent
[+] Anti-Debug: NtGlobalFlag (PEB)
[+] Anti-Debug: Debugger Process List
[+] Anti-Debug: Hardware Breakpoints
[+] ETW Evasion: Simple Patch
[+] AMSI Evasion: Simple Patch
[+] NTDLL Unhooking
[+] EnumDesktopWindows Callback Execution
[+] Function Stomping Injection
[+] CTAES Encryption
[*] ============================

[*] Reading payload from: shellcode.bin
[+] Payload read successfully (276 bytes)
[+] Payload encrypted with CTAES (288 bytes)
[!] IMPORTANT: The final executable will require --key and --iv arguments:
    Usage: PickerPacker_Packed.exe --key
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--iv 0123456789abcdef0123456789abcdef
[*] Detected payload type: Shellcode
[*] Using execution method: EnumDesktopWindows Callback Execution
[*] Writing loader stub...
[*] Compiling loader...
[*] Compile command: cargobuild --release --features
ShellcodeExecuteEnumDesktopWindows --features InjectionFunctionStomping
 --features CheckAntiDebugProcessDebugFlags --features
CheckAntiDebugSystemDebugControl --features CheckAntiDebugRemoteDebugger
 --features CheckAntiDebugNtGlobalFlag --features CheckAntiDebugProcessList
 --features CheckAntiDebugHardwareBreakpoints --features EvasionETWSimple
 --features EvasionAMSISimplePatch --features EvasionNtdllUnhooking
--features CTAES --manifest-path ./loader/Cargo.toml
--target x86_64-pc-windows-msvc
[+] Compilation successful!
[*] Moving executable to root directory...
[+] Packed executable created: PickerPacker_Packed.exe

[!] Remember to run with: PickerPacker_Packed.exe --key
 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
--iv 0123456789abcdef0123456789abcdef
```

---

## Documentation

- **[FEATURES.md](FEATURES.md)** - Complete feature documentation with all 64 features categorized
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Guidelines for contributing new features
- **[LICENSE](LICENSE)** - License information. This project is licensed under the MIT License.

---

## 🗺️ Roadmap

- [ ] **Multi-Payload Support** - Native PE, DLL, .NET assembly support
- [ ] **Delta Timing Checks**
- [ ] **More Anti-vm and Anti-Debug Checks**
- [ ] **Payload Compression**
- [ ] **String obfuscation**
- [ ] **IAT Spoofing**
- [ ] **Control Flow Flattening (Anti-Disassembly)**

--------------------

## Credits & Acknowledgments

- **[rtecCyberSec/Packer_Development](https://github.com/rtecCyberSec/Packer_Development)** - Primary inspiration for this project
- **[janoglezcampos/rust_syscalls](https://github.com/janoglezcampos/rust_syscalls)** - Indirect syscall implementation

This project incorporates techniques and code snippets from:
- **[Maldev Academy](https://maldevacademy.com/)** - Malware development educational resources
- **[Whitecat18/Rust-for-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development)** - Rust malware development examples
- **[joaoviictorti/RustRedOps](https://github.com/joaoviictorti/RustRedOps)** - Offensive Rust techniques
-------
**Disclaimer** - This tool is provided for educational purposes and authorized security testing only. Users are responsible for compliance with all applicable laws and regulations.
