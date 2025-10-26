// ============================================================================
// Configuration Module
// ============================================================================

pub struct PackerConfig {
    pub do_message_box: bool,
    pub do_calculation: bool,
    pub embedded_payload: bool,
    pub do_default_execution: bool,
    pub do_tinyaes: bool,
    pub aes_key: String,
    pub aes_iv: String,
    pub input_file: String,
    pub shellcode_file: String,
}

impl PackerConfig {
    pub fn new() -> Self {
        Self {
            do_message_box: false,
            do_calculation: false,
            embedded_payload: true,
            do_default_execution: false,
            do_tinyaes: false,
            aes_key: String::new(),
            aes_iv: String::new(),
            input_file: String::new(),
            shellcode_file: String::new(),
        }
    }

    pub fn parse_args(&mut self, args: &[String]) {
        for i in 0..args.len() {
            match args[i].as_str() {
                "--messageBox" => self.do_message_box = true,
                "--randomCalculation" => self.do_calculation = true,
                "--DefaultExecution" => self.do_default_execution = true,
                "--tinyaes" => self.do_tinyaes = true,
                "--key" if i < args.len() - 1 => self.aes_key = args[i + 1].clone(),
                "--iv" if i < args.len() - 1 => self.aes_iv = args[i + 1].clone(),
                "--shellcodeFile" if i < args.len() - 1 => self.shellcode_file = args[i + 1].clone(),
                "--input" if i < args.len() - 1 => self.input_file = args[i + 1].clone(),
                _ => {}
            }
        }

        // Auto-enable default execution if input file is provided
        if !self.input_file.is_empty() && !self.do_default_execution {
            self.do_default_execution = true;
        }

        // Disable embedded mode if external shellcode file is specified
        if !self.shellcode_file.is_empty() {
            self.embedded_payload = false;
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate input file is provided
        if self.input_file.is_empty() {
            return Err("Please provide an input file with --input <filename>".to_string());
        }

        // Validate AES parameters if TinyAES is enabled
        if self.do_tinyaes {
            if self.aes_key.is_empty() || self.aes_iv.is_empty() {
                return Err(
                    "[-] Error: --tinyaes requires both --key and --iv arguments\n\
                     Key must be 32 bytes (64 hex characters)\n\
                     IV must be 16 bytes (32 hex characters)".to_string()
                );
            }

            if self.aes_key.len() != 64 {
                return Err("[-] Error: AES key must be exactly 64 hex characters (32 bytes)".to_string());
            }

            if self.aes_iv.len() != 32 {
                return Err("[-] Error: AES IV must be exactly 32 hex characters (16 bytes)".to_string());
            }
        }

        Ok(())
    }
}
