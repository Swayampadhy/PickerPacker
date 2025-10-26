#[cfg(feature = "TinyAES")]
fn main() {
    cc::Build::new()
        .file("TinyAES.c")
        .compile("tinyaes");
    
    println!("cargo:rerun-if-changed=TinyAES.c");
}

#[cfg(not(feature = "TinyAES"))]
fn main() {
    // Do nothing if TinyAES feature is not enabled
}
