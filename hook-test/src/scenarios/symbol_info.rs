// symbol_info 场景：验证 addr_info 能将地址定位到 so / 基址
// bionic dladdr 对 sym_name 非强保证；细粒度符号需 ELF 解析

use core::ffi::c_void;

use srx_inline_hook::addr_info;

use crate::test_ctx::target_add;

pub fn addr_info_basic() {
    // 本进程函数：定位到当前可执行 / 宿主 so
    let info = addr_info(target_add as *const c_void).expect("addr_info(target_add)");
    assert_ne!(info.lib_base, 0, "symbol_info check failed");
    let self_path = info.lib_path.as_deref().unwrap_or("");
    assert!(
        !self_path.is_empty(),
        "symbol_info check failed: {:?}",
        info.lib_path
    );

    // libc 导出符号：dlsym(RTLD_DEFAULT, "strlen") 绕过 LLVM 内联
    let name = c"strlen";
    // SAFETY: RTLD_DEFAULT 查找当前全局命名空间
    let strlen_addr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    assert!(!strlen_addr.is_null(), "symbol_info check failed");

    let libc_info = addr_info(strlen_addr).expect("addr_info(strlen)");
    assert_ne!(libc_info.lib_base, 0, "symbol_info check failed");
    let path = libc_info.lib_path.as_deref().unwrap_or("");
    assert!(
        path.contains("libc.so"),
        "symbol_info check failed: {}",
        path
    );
    // lib_base < sym_addr 推定 dlsym 落在 libc 代码区；dli_saddr 可能为 0 时放行
    if libc_info.sym_addr != 0 {
        assert!(
            libc_info.sym_addr >= libc_info.lib_base,
            "symbol_info check failed: {:#x}, {:#x}",
            libc_info.sym_addr,
            libc_info.lib_base
        );
    }

    println!(
        "addr_info_basic: PASS (self={}, libc={} base={:#x} sym={:?})",
        self_path, path, libc_info.lib_base, libc_info.sym_name
    );
}
