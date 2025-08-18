fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let config_path = std::path::Path::new(&crate_dir).join("cbindgen.toml");

    // Rebuild if inputs change
    println!("cargo:rerun-if-changed={}", config_path.display());
    println!("cargo:rerun-if-changed={crate_dir}/src");
    println!("cargo:rerun-if-changed={crate_dir}/Cargo.toml");
    println!("cargo:rerun-if-changed={crate_dir}/build.rs");

    let config = cbindgen::Config::from_file(&config_path).unwrap_or_default();

    let bindings = cbindgen::Builder::new()
        .with_config(config)
        .with_crate(&crate_dir)
        .generate()
        .expect("Unable to generate bindings");

    // Always write to OUT_DIR
    let out_header = std::path::Path::new(&out_dir).join("runar_ffi.h");
    if !bindings.write_to_file(&out_header) {
        println!("cargo:rerun-if-changed={}", out_header.display());
    } else {
        println!(
            "cargo:warning=Generated header at OUT_DIR: {}",
            out_header.display()
        );
    }

    // Also write to a stable include/ path in the crate for packaging/CI convenience
    let dest = if let Ok(custom) = std::env::var("RUNAR_FFI_HEADER_OUT") {
        std::path::PathBuf::from(custom)
    } else {
        let include_dir = std::path::Path::new(&crate_dir).join("include");
        let _ = std::fs::create_dir_all(&include_dir);
        include_dir.join("runar_ffi.h")
    };
    if bindings.write_to_file(&dest) {
        println!("cargo:warning=Generated header at {}", dest.display());
    } else {
        // up-to-date; no message
    }
}
