// get_errno: hook/unhook/init 各出口正确写 TLS 最近错误码
// 同线程连续操作应覆写；只读 getters 不影响值

use core::ffi::c_void;
use core::ptr;

use srx_inline_hook::{
    Errno, get_errno, hook_single, is_debug, list_hooks, trampoline_stats, unhook,
};

use crate::test_ctx::{STUB_ADD, clear, install, replacement_add, target_add};

pub fn get_errno_basic() {
    // init 在 main 中早已成功调过，此处读到 Ok（若此线程曾经历过 API，则保持）
    let _ = get_errno();

    // 触发 InvalidArg：null target
    // SAFETY: 空参专测 InvalidArg 路径
    let bad = unsafe { hook_single(ptr::null_mut(), replacement_add as *const c_void) };
    assert!(bad.is_err(), "errno_tls check failed");
    assert_eq!(get_errno(), Errno::InvalidArg, "errno_tls check failed");

    // 只读 getters 不改 tls_errno
    let _ = is_debug();
    let _ = list_hooks();
    let _ = trampoline_stats();
    assert_eq!(get_errno(), Errno::InvalidArg, "errno_tls check failed");

    // 成功 hook 应写 Ok
    let stub = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(
        get_errno(),
        Errno::Ok,
        "errno_tls check failed: {:?}",
        get_errno()
    );
    assert_eq!(target_add(1, 2), 1003);

    // duplicate hook 写 HookUniqueDup
    // SAFETY: target_add 已在表中
    let dup = unsafe { hook_single(target_add as *mut c_void, replacement_add as *const c_void) };
    assert!(dup.is_err(), "errno_tls check failed");
    assert_eq!(get_errno(), Errno::HookUniqueDup, "errno_tls check failed");

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);
    assert_eq!(get_errno(), Errno::Ok, "errno_tls check failed");

    // 对已 unhook 的 stub 再次 unhook 写 UnhookNotFound
    // SAFETY: stub 已 unhook，仅用于触发 NotFound
    let miss = unsafe { unhook(stub) };
    assert!(miss.is_err(), "errno_tls check failed");
    assert_eq!(get_errno(), Errno::UnhookNotFound, "errno_tls check failed");

    println!("get_errno_basic: PASS");
}
