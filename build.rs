fn main() {
    // Compile TinyAES
    cc::Build::new()
        .file("template/aes/TinyAES.c")
        .compile("tinyaes");
    
    println!("cargo:rerun-if-changed=template/aes/TinyAES.c");
    
    // Compile CTAES
    cc::Build::new()
        .file("template/aes/CtAes.c")
        .compile("ctaes");
    
    println!("cargo:rerun-if-changed=template/aes/CtAes.c");
}
