// ============================================================================
// AES Encryption Module
// ============================================================================

#[repr(C)]
struct AesCtx {
    round_key: [u8; 240],
    iv: [u8; 16],
}

unsafe extern "C" {
    fn AES_init_ctx_iv(ctx: *mut AesCtx, key: *const u8, iv: *const u8);
    fn AES_CBC_encrypt_buffer(ctx: *mut AesCtx, buf: *mut u8, length: usize);
}

pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
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

pub fn aes_encrypt_payload(raw_data_buffer: &[u8], aes_key: &[u8], aes_iv: &[u8]) -> Option<Vec<u8>> {
    if raw_data_buffer.is_empty() || aes_key.is_empty() || aes_iv.is_empty() {
        return None;
    }

    let mut new_buffer = Vec::from(raw_data_buffer);
    let raw_buffer_size = raw_data_buffer.len();
    let mut new_buffer_size = raw_buffer_size;

    // Add PKCS#7 padding
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
