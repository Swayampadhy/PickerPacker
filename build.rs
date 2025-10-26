fn main() {
    // Compile TinyAES
    cc::Build::new()
        .file("template/TinyAES.c")
        .compile("tinyaes");
    
    println!("cargo:rerun-if-changed=template/TinyAES.c");
    
    // Compile CTAES
    cc::Build::new()
        .file("template/CtAes.c")
        .compile("ctaes");
    
    println!("cargo:rerun-if-changed=template/CtAes.c");
}
