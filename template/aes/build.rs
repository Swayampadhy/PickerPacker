fn main() {
    #[cfg(feature = "TinyAES")]
    {
        cc::Build::new()
            .file("TinyAES.c")
            .compile("tinyaes");
        
        println!("cargo:rerun-if-changed=TinyAES.c");
    }
    
    #[cfg(feature = "CTAES")]
    {
        cc::Build::new()
            .file("CtAes.c")
            .compile("ctaes");
        
        println!("cargo:rerun-if-changed=CtAes.c");
    }
}
