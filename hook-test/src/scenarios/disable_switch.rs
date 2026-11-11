// 全局禁用开关：开启后拒绝新 hook，已有 hook 保持生效
// 关闭后恢复安装和卸载能力

use core::ffi::c_void;
use core::ptr;

use srx_inline_hook::{Errno, hook_single, hook_sym_name, is_disabled, set_disabled, unhook};

use crate::test_ctx::{STUB_ADD, clear, install, replacement_add, target_add};

pub fn global_disable_switch() {
    assert!(!is_disabled(), "disable_switch check failed");

    // 已装 hook 不受 disabled 影响
    let stub = install(&STUB_ADD, target_add, replacement_add);
    set_disabled(true);
    assert!(is_disabled());

    // 新 hook 先走禁用检查，不进入重复安装分支
    // SAFETY: target / replacement 为本进程可执行地址
    let blocked =
        unsafe { hook_single(target_add as *mut c_void, replacement_add as *const c_void) };
    assert!(matches!(blocked, Err(Errno::Disabled)));

    // hook_sym_name 路径的 disabled 检查应在 dlopen 之前：即便参数合法也先返回 Disabled
    let libc = c"libc.so";
    let sym = c"strlen";
    // SAFETY: libc.so / strlen 有效；disabled 下应在 dlopen 前返回
    let blocked_sn =
        unsafe { hook_sym_name(libc, sym, replacement_add as *const c_void, ptr::null_mut()) };
    assert!(
        matches!(blocked_sn, Err(Errno::Disabled)),
        "disable_switch check failed: {:?}",
        blocked_sn
    );

    // 已装 hook 仍正常
    assert_eq!(target_add(3, 4), 1007);

    // 禁用开启时 unhook 也返回 Disabled(45)
    // SAFETY: stub 有效，仅验证前置检查顺序
    let blocked_unhook = unsafe { unhook(stub) };
    assert!(
        matches!(blocked_unhook, Err(Errno::Disabled)),
        "disable_switch check failed: {:?}",
        blocked_unhook
    );
    // 再验证 hook 未被错误拆除：target_add 仍走 replacement
    assert_eq!(target_add(3, 4), 1007);

    // 解闸后可继续 hook / unhook
    set_disabled(false);
    assert!(!is_disabled());

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);
    assert_eq!(target_add(3, 4), 7);
    println!("global_disable_switch: PASS");
}
