#[cfg(feature = "TinyAES")]
#[repr(C)]
pub struct AesCtx {
    round_key: [u8; 240],
    iv: [u8; 16],
}

#[cfg(feature = "TinyAES")]
unsafe extern "C" {
    fn AES_init_ctx_iv(ctx: *mut AesCtx, key: *const u8, iv: *const u8);
    fn AES_CBC_encrypt_buffer(ctx: *mut AesCtx, buf: *mut u8, length: usize);
    fn AES_CBC_decrypt_buffer(ctx: *mut AesCtx, buf: *mut u8, length: usize);
}

#[cfg(feature = "TinyAES")]
pub fn aes_encrypt(raw_data_buffer: &[u8], aes_key: &[u8], aes_iv: &[u8]) -> Option<Vec<u8>> {
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

#[cfg(feature = "TinyAES")]
pub fn aes_decrypt(encrypted_buffer: &[u8], aes_key: &[u8], aes_iv: &[u8]) -> Option<Vec<u8>> {
    if encrypted_buffer.is_empty() || aes_key.is_empty() || aes_iv.is_empty() {
        return None;
    }

    let mut decrypted_buffer = Vec::from(encrypted_buffer);
    let buffer_size = encrypted_buffer.len();

    let mut aes_ctx: AesCtx = unsafe { std::mem::zeroed() };
    unsafe {
        AES_init_ctx_iv(&mut aes_ctx, aes_key.as_ptr(), aes_iv.as_ptr());
        AES_CBC_decrypt_buffer(&mut aes_ctx, decrypted_buffer.as_mut_ptr(), buffer_size);
    }

    Some(decrypted_buffer)
}
