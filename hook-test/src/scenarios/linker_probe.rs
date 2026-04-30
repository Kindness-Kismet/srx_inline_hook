// linker64 基址解析检查：A12+ dl_iterate_phdr 必须拿到有意义的 base；返回地址应在 /proc/self/maps 范围内

use srx_inline_hook::{
    find_linker_symbol, find_linker_symbol_by_symtab, find_linker64_base, linker_ctor_hit_count,
    linker_dtor_hit_count, linker_hook_stub_count, linker_hooks_installed,
    reset_linker_hook_counters,
};

pub fn linker_base_resolution() {
    let base = find_linker64_base().expect("linker_probe check failed");
    assert!(base != 0, "linker_probe check failed");
    // 典型 Android linker64 落在 0x7000_0000_0000 上下；至少高于 heap 起点 0x100000
    assert!(base > 0x0010_0000, "linker_probe check failed: {:x}", base);
    println!("linker_base_resolution: PASS (linker64 base=0x{:x})", base);
}

pub fn linker_dynsym_lookup() {
    let base = find_linker64_base().expect("linker_probe check failed");
    // __loader_dlopen 是 bionic linker 导出到 dynsym 的内部符号，A12+ 稳定
    let addr = find_linker_symbol(c"__loader_dlopen").expect("linker_probe check failed");
    assert!(
        addr > base,
        "linker_probe check failed: {:x}, {:x}",
        addr,
        base
    );
    // 保守边界：linker64 自身不会超过 4 MiB
    assert!(
        addr - base < 4 * 1024 * 1024,
        "linker_probe check failed: {:x}",
        addr - base
    );
    println!(
        "linker_dynsym_lookup: PASS (__loader_dlopen=0x{:x} offset=0x{:x})",
        addr,
        addr - base
    );
}

pub fn linker_symtab_lookup() {
    let base = find_linker64_base().expect("linker_probe check failed");
    let addr = find_linker_symbol_by_symtab(c"__dl__ZN6soinfo17call_constructorsEv")
        .expect("linker_probe check failed");
    assert!(
        addr > base,
        "linker_probe check failed: {:x}, {:x}",
        addr,
        base
    );
    assert!(
        addr - base < 4 * 1024 * 1024,
        "linker_probe check failed: {:x}",
        addr - base
    );
    println!(
        "linker_symtab_lookup: PASS (call_constructors=0x{:x} offset=0x{:x})",
        addr,
        addr - base
    );
}

pub fn linker_hook_installation() {
    assert!(linker_hooks_installed(), "linker_probe check failed");
    assert_eq!(linker_hook_stub_count(), 2, "linker_probe check failed");

    reset_linker_hook_counters();
    let before_ctor = linker_ctor_hit_count();
    let before_dtor = linker_dtor_hit_count();

    // SAFETY: 路径为推送目录下同目录 so；dlopen/dlclose 仅触发测试 so 的 ctor/dtor
    let handle = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "linker_probe check failed");
    // SAFETY: handle 来自成功 dlopen
    unsafe { libc::dlclose(handle) };

    let after_ctor = linker_ctor_hit_count();
    let after_dtor = linker_dtor_hit_count();
    assert!(after_ctor > before_ctor, "linker_probe check failed");
    assert!(after_dtor > before_dtor, "linker_probe check failed");

    println!(
        "linker_hook_installation: PASS (stubs={} ctor_hits={} dtor_hits={})",
        linker_hook_stub_count(),
        after_ctor,
        after_dtor
    );
}
