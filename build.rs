fn main() {
    cc::Build::new()
        .file("template/TinyAES.c")
        .compile("tinyaes");
    
    println!("cargo:rerun-if-changed=template/TinyAES.c");
}
