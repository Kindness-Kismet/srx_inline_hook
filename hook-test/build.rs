use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    compile_header_api();
}

fn compile_header_api() {
    let target = env::var("TARGET").expect("TARGET");
    if target != "x86_64-linux-android" && target != "aarch64-linux-android" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir.parent().expect("workspace root");
    let include_dir = workspace_dir.join("include");
    let api_dir = manifest_dir.join("header-api");
    let stub_include_dir = api_dir.join("include");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    for file in [
        api_dir.join("basic_api.c"),
        api_dir.join("call_prev.c"),
        api_dir.join("call_prev.cpp"),
        api_dir.join("callback_typedef.c"),
        api_dir.join("cpu_context_macro.c"),
        api_dir.join("errno_macro.c"),
        api_dir.join("hook_api_v2.c"),
        api_dir.join("macro_constants.c"),
        api_dir.join("pop_stack.c"),
        api_dir.join("stack_scope.cpp"),
        api_dir.join("version_macro.c"),
    ] {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("srx_inline_hook.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        stub_include_dir.join("link.h").display()
    );

    let Some(ndk_home) = find_ndk_home() else {
        println!("cargo:warning=skip header API check: Android NDK not found");
        return;
    };

    let clang_bin = ndk_home
        .join("toolchains")
        .join("llvm")
        .join("prebuilt")
        .join(ndk_prebuilt_tag())
        .join("bin");
    let api = env::var("ANDROID_PLATFORM")
        .ok()
        .and_then(|v| parse_api(&v))
        .unwrap_or(31);
    let c_compiler = clang_bin.join(format!(
        "{}{}-clang{}",
        toolchain_prefix(&target),
        api,
        exe_suffix()
    ));
    let cpp_compiler = clang_bin.join(format!(
        "{}{}-clang++{}",
        toolchain_prefix(&target),
        api,
        exe_suffix()
    ));

    if !c_compiler.exists() || !cpp_compiler.exists() {
        println!(
            "cargo:warning=skip header API check: missing Android clang for {} in {}",
            target,
            clang_bin.display()
        );
        return;
    }

    let jobs = [
        ("basic_api.c", false),
        ("call_prev.c", false),
        ("call_prev.cpp", true),
        ("callback_typedef.c", false),
        ("cpu_context_macro.c", false),
        ("errno_macro.c", false),
        ("hook_api_v2.c", false),
        ("macro_constants.c", false),
        ("pop_stack.c", false),
        ("stack_scope.cpp", true),
        ("version_macro.c", false),
    ];

    for (name, is_cpp) in jobs {
        let compiler = if is_cpp { &cpp_compiler } else { &c_compiler };
        let source = api_dir.join(name);
        let object = out_dir.join(format!("{}.o", name.replace('.', "_")));
        compile_one(compiler, &source, &object, &include_dir, &stub_include_dir);
    }
}

fn compile_one(
    compiler: &Path,
    source: &Path,
    object: &Path,
    include_dir: &Path,
    stub_include_dir: &Path,
) {
    let output = Command::new(compiler)
        .arg("-I")
        .arg(include_dir)
        .arg("-I")
        .arg(stub_include_dir)
        .arg("-c")
        .arg(source)
        .arg("-o")
        .arg(object)
        .output()
        .expect("run header API compiler");

    if !output.status.success() {
        panic!(
            "header API check compile failed for {}\nstdout:\n{}\nstderr:\n{}",
            source.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn find_ndk_home() -> Option<PathBuf> {
    ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"]
        .into_iter()
        .filter_map(|key| env::var(key).ok())
        .map(|raw| normalize_host_path(&raw))
        .find(|path| path.exists())
        .or_else(find_ndk_from_android_sdk)
}

fn find_ndk_from_android_sdk() -> Option<PathBuf> {
    let sdk = ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .into_iter()
        .filter_map(|key| env::var(key).ok())
        .map(|raw| normalize_host_path(&raw))
        .find(|path| path.exists())?;
    std::fs::read_dir(sdk.join("ndk"))
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .max_by(|a, b| a.file_name().cmp(&b.file_name()))
}

fn normalize_host_path(raw: &str) -> PathBuf {
    if cfg!(windows) {
        let bytes = raw.as_bytes();
        if raw.starts_with('/')
            && raw.len() > 2
            && bytes[1].is_ascii_alphabetic()
            && bytes[2] == b'/'
        {
            let drive = (bytes[1] as char).to_ascii_uppercase();
            return PathBuf::from(format!("{}:/{}", drive, &raw[3..]));
        }
    }
    PathBuf::from(raw)
}

fn ndk_prebuilt_tag() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows-x86_64"
    } else if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else {
        "linux-x86_64"
    }
}

fn toolchain_prefix(target: &str) -> &'static str {
    match target {
        "x86_64-linux-android" => "x86_64-linux-android",
        "aarch64-linux-android" => "aarch64-linux-android",
        _ => unreachable!("unsupported target"),
    }
}

fn parse_api(value: &str) -> Option<u32> {
    value
        .rsplit_once('-')
        .and_then(|(_, tail)| tail.parse().ok())
        .or_else(|| value.parse().ok())
}

fn exe_suffix() -> &'static str {
    if cfg!(windows) { ".cmd" } else { "" }
}
