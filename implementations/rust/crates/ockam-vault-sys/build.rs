extern crate bindgen;
extern crate cmake;
extern crate walkdir;
extern crate which;

use std::env;
use std::path::PathBuf;

use bindgen::EnumVariation;
use walkdir::WalkDir;
use which::which;

const ENV_LLVM_PREFIX: &'static str = "LLVM_PREFIX";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Construct path to C implementation
    let cwd = env::current_dir().unwrap();
    let crates_dir = cwd.parent().unwrap();
    let rust_dir = crates_dir.parent().unwrap();
    let implementations_dir = rust_dir.parent().unwrap();
    let c_dir = implementations_dir.join("c");
    let include_dir = c_dir.join("include");
    let kal_dir = c_dir.join("source/ockam/kal");
    let vault_dir = c_dir.join("source/ockam/vault");
    let config_file = cwd.join("c_src/vault_config.h");

    let ockam_kal_output = out_dir.join("ockam_kal");
    let ockam_vault_output = out_dir.join("ockam_vault");

    std::fs::create_dir_all(&ockam_kal_output).unwrap();
    let ockam_kal_path = cmake::Config::new(kal_dir)
        .always_configure(true)
        .define("OCKAM_C_BASE", c_dir.as_os_str())
        .define("KAL_LINUX", "ON")
        .cflag(&format!("-I{}", include_dir.display()))
        .out_dir(ockam_kal_output)
        .build_target("ockam_kal")
        .build();

    // Build host version of Ockam Vault against OpenSSL
    std::fs::create_dir_all(&ockam_vault_output).unwrap();
    let ockam_vault_path = cmake::Config::new(vault_dir)
        .always_configure(true)
        .define("OCKAM_C_BASE", c_dir.as_os_str())
        .define("VAULT_HOST_OCKAM", "OFF")
        .define("VAULT_HOST_MBEDCRYPTO", "ON")
        .cflag(&format!("-I{}", include_dir.display()))
        .cflag(&format!(
            "-DOCKAM_VAULT_CONFIG_FILE='\"{}\"'",
            config_file.display()
        ))
        .out_dir(ockam_vault_output)
        .build_target("all")
        .build();

    // Link against built library
    println!(
        "cargo:rustc-link-search=native={}",
        ockam_kal_path.join("build").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        ockam_vault_path.join("build").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        ockam_vault_path.join("build/mbed-crypto/library").display()
    );
    println!("cargo:rustc-link-lib=static=ockam_kal");
    println!("cargo:rustc-link-lib=static=ockam_vault");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    // Expose include path to downstream crates via DEP_OCKAM_VAULT_INCLUDE
    println!("cargo:include={}", include_dir.display());
    // Rerun build if any of the include paths change
    let walker = WalkDir::new(&include_dir).into_iter();
    for entry in walker.filter_entry(|e| e.file_type().is_file()) {
        println!("cargo:rerun-if-changed={}", entry.unwrap().path().display());
    }

    // Generate bindings

    // Generate bindings if llvm-config is present
    if let Ok(llvm_config) = which("llvm-config") {
        // Rebuild bindings if we modify the wrapper
        println!("cargo:rerun-if-changed=c_src/vault.h");
        generate_bindings(llvm_config, include_dir, out_dir.join("bindings.rs"));
        return;
    }

    // Otherwise, try to find llvm-config and generate bindings if found
    if let Some(llvm_prefix) = env::var_os(ENV_LLVM_PREFIX) {
        let llvm_config = PathBuf::from(llvm_prefix).join("bin/llvm-config");
        if llvm_config.exists() {
            println!("cargo:rerun-if-changed=c_src/vault.h");
            generate_bindings(llvm_config, include_dir, out_dir.join("bindings.rs"));
            return;
        }
    }

    println!("cargo:rerun-if-env-changed={}", ENV_LLVM_PREFIX);
    println!(
        "cargo:warning={}",
        "LLVM_PREFIX was not set, and cannot find llvm-config, will not regenerate bindings"
    );
}

fn generate_bindings(llvm_config: PathBuf, include_dir: PathBuf, out_path: PathBuf) {
    env::set_var("LLVM_CONFIG_PATH", &llvm_config);
    let bindings = bindgen::Builder::default()
        .header("c_src/vault.h")
        .use_core()
        .detect_include_paths(true)
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        })
        .prepend_enum_name(false)
        .layout_tests(false)
        .ignore_methods()
        .whitelist_function("ockam_.*")
        .whitelist_type("(OCKAM|VAULT).*")
        .clang_arg("-I")
        .clang_arg(include_dir.to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Failed to generate bindings to Ockam Vault!");

    bindings.write_to_file(out_path).unwrap();
}
