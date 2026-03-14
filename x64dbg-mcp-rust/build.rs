use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    // We only link to x64bridge.lib and x64dbg.lib or x32bridge.lib and x32dbg.lib
    // For simplicity, we assume building for 64-bit first
    let sdk_path = std::fs::canonicalize("../vendor/x64dbg-pluginsdk").unwrap();
    println!("cargo:rustc-link-search=native={}", sdk_path.display());

    if cfg!(target_pointer_width = "64") {
        println!("cargo:rustc-link-lib=x64bridge");
        println!("cargo:rustc-link-lib=x64dbg");
    } else {
        println!("cargo:rustc-link-lib=x32bridge");
        println!("cargo:rustc-link-lib=x32dbg");
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", sdk_path.display()))
        // Windows specific macros
        .clang_arg("-D_WIN64")
        .clang_arg("-DWIN32_LEAN_AND_MEAN")
        // Don't generate bindings for basic Windows stuff if possible, but keep it simple
        .allowlist_function(".*(plugin|Dbg|Gui|Bridge|Script).*")
        .allowlist_type("(?i).*(PLUG_|BRIDGE|CB_TYPE|ExpressionValue|ValueType|duint|BASIC_INSTRUCTION_INFO|SYMBOL|TCP|HANDLE|HEAP|WINDOW|PATCH|BridgeCF|ListInfo|RECT|XREF|CALLSTACK|DISASM|BPMAP|THREADLIST|MEMMAP).*")
        .allowlist_var("(?i).*(PLUG_|CB_|SYMBOL|BPX|BridgeCF).*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
