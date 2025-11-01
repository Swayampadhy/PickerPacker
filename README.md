# PickerPacker

**This project is currently under construction** 
This is a pre-release version.

A customizable lightweight packer written in Rust with multiple execution methods and encryption capabilities. Designed to provide the operator with granular feature selection support i.e. Users can mix and match any attack chain they want with the payload. 

NOTE: **You can add or change code in the "template\benign.rs" folder to modify how the "benign" part of the packer works. Refer to "template\benign.rs" for more instructions**

## Features

- **Multiple Execution Methods**: 35+ different shellcode execution techniques using Windows callbacks and APIs
- **Encryption Support**: 
  - TinyAES encryption
  - CTAES (Constant-Time AES) encryption
  - No encryption option
- **Optional Syscalls**: Feature-gated `rust_syscalls` support for injection techniques
- **Embedded Payload**: Compile-time payload embedding with runtime decryption

## Project Status

🚧 **Under Active Development** 🚧

This project is being actively developed and tested. Features, APIs, and functionality may change without notice.

## Build From Source

```powershell
# Build the packer
cargo build --release

# Execute the Packer Executable With Required feature arguments
.\target\release\PickerPacker.exe --input <Your Payload File> --execution-method <desired execution method>
```

## Usage

```powershell
# Example usage
.\PickerPacker.exe --input payload.bin --execution-method fiber --encrypt ctaes --key <hex_key> --iv <hex_iv>

# Run packed executable with encryption
.\PickerPacker_Packed.exe --key <hex_key> --iv <hex_iv>
```

### Sample Output

```
PS E:\Projects\PickerPacker> .\target\release\PickerPacker.exe
--input shellcode.bin --execution-method enumresourcetypesw

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

    

[*] ===== Feature Summary =====
[+] EnumResourceTypesW Callback Execution
[+] Default Local Injection
[+] Embedded Payload
[*] ============================

[*] Reading payload from: shellcode.bin
[+] Payload read successfully (276 bytes)
[*] Writing loader stub...
[*] Compiling loader...
[*] Compile command: cargo build --release --features
ShellcodeExecuteEnumResourceTypesW --features InjectionDefaultLocal
--features embedded  --manifest-path ./loader/Cargo.toml --target
x86_64-pc-windows-msvc
[+] Compilation successful!
[*] Moving executable to root directory...
[+] Packed executable created: ./PickerPacker_Packed.exe
```

## Execution Methods

The packer supports 35+ different execution techniques including:
- Default allocation and execution
- Fiber-based execution
- Callback-based methods (Timer Queue, EnumUILanguages, etc.)
- Process injection variants

## License

See [LICENSE](LICENSE) file for details.

## Credits
- [rtecCyberSec/Packer_Development](https://github.com/rtecCyberSec/Packer_Development)
- [Maldev Academy](https://maldevacademy.com/)
- [janoglezcampos/Rust_Syscalls](https://github.com/janoglezcampos/rust_syscalls)
- [Whitecat18/Rust-For-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development)
- [joaoviictorti/RustRedOps](https://github.com/joaoviictorti/RustRedOps)

---

**Note**: This is a research and development project. Use responsibly and only in authorized testing environments.
