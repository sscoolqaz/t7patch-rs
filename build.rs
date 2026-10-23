//! Links the vendored `MinHook` static library for the Windows MSVC target.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor/minhook/lib/libMinHook.x64.lib");

    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("windows") && target.contains("x86_64") {
        let lib_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
            .join("vendor/minhook/lib");
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static=libMinHook.x64");
    }
}
