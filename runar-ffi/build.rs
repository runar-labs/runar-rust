fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let config_path = std::path::Path::new(&crate_dir).join("cbindgen.toml");
    let out_path = std::path::Path::new(&crate_dir).join("runar_ffi.h");

    let config = match cbindgen::Config::from_file(&config_path) {
        Ok(c) => c,
        Err(_) => cbindgen::Config::default(),
    };

    cbindgen::Builder::new()
        .with_config(config)
        .with_crate(&crate_dir)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path);
}


