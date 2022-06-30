use std::env;
use std::path::PathBuf;

fn main() {
    let dst = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = dst.join("sysrepo2.rs");

    #[cfg(feature = "use_bindgen")]
    {
        // Generate Rust FFI to libsysrepo.
        println!("cargo:rerun-if-changed=wrapper.h");
        let bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .derive_default(true)
            .default_enum_style(bindgen::EnumVariation::ModuleConsts)
            .generate()
            .expect("Unable to generate sysrepo2 bindings");
        bindings
            .write_to_file(out_file)
            .expect("Couldn't write sysrepo2 bindings!");
    }

    #[cfg(not(feature = "use_bindgen"))]
    {
        let mut pregen_bindings = PathBuf::new();
        pregen_bindings.push(env::var("CARGO_MANIFEST_DIR").unwrap());
        pregen_bindings.push("pre-generated-bindings");
        pregen_bindings.push("sysrepo2-df89fc02e301cc8f2e6b30ec37b990f52ca1d5c4.rs");

        std::fs::copy(&pregen_bindings, &out_file)
            .expect("Unable to copy pre-generated sysrepo2 bindings");
    }

    #[cfg(not(feature = "bundled"))]
    println!("cargo:rustc-link-lib=sysrepo");
}
