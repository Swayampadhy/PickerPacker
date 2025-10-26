// ============================================================================
// Tiny-AES Module - AES-256-CBC encryption/decryption using Tiny-AES library
// ============================================================================

#[cfg(feature = "TinyAES")]
#[repr(C)]
pub struct AesCtx {
    round_key: [u8; 240],
    iv: [u8; 16],
}

#[cfg(feature = "TinyAES")]
unsafe extern "C" {
    fn AES_init_ctx_iv(ctx: *mut AesCtx, key: *const u8, iv: *const u8);
    fn AES_CBC_decrypt_buffer(ctx: *mut AesCtx, buf: *mut u8, length: usize);
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

// ============================================================================
// CTAES Module - AES-256-CBC encryption/decryption using CTAES library
// ============================================================================

#[cfg(feature = "CTAES")]
#[repr(C)]
struct AES_STATE {
    slice: [u16; 8],
}

#[cfg(feature = "CTAES")]
#[repr(C)]
struct AES256_ctx {
    rk: [AES_STATE; 15],
}

#[cfg(feature = "CTAES")]
#[repr(C)]
struct AES256_CBC_ctx {
    ctx: AES256_ctx,
    iv: [u8; 16],
}

#[cfg(feature = "CTAES")]
unsafe extern "C" {
    fn AES256_CBC_init(ctx: *mut AES256_CBC_ctx, key16: *const u8, iv: *const u8);
    fn AES256_CBC_decrypt(ctx: *mut AES256_CBC_ctx, blocks: usize, plain: *mut u8, encrypted: *const u8);
}

/// Decrypt data using CTAES AES-256-CBC
#[cfg(feature = "CTAES")]
pub fn ctaes_decrypt(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    if encrypted.is_empty() || key.is_empty() || iv.is_empty() {
        return None;
    }

    if key.len() != 32 || iv.len() != 16 {
        return None;
    }

    if encrypted.len() % 16 != 0 {
        return None;
    }

    let mut decrypted = vec![0u8; encrypted.len()];
    let mut ctx: AES256_CBC_ctx = unsafe { std::mem::zeroed() };
    
    unsafe {
        AES256_CBC_init(&mut ctx, key.as_ptr(), iv.as_ptr());
        AES256_CBC_decrypt(&mut ctx, encrypted.len() / 16, decrypted.as_mut_ptr(), encrypted.as_ptr());
    }

    Some(decrypted)
}
