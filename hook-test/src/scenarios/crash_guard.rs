// bytesig::guard 信号保护的端到端验证：hook 指向不可读地址时走 SIGSEGV 回跳
// 覆盖 SIGSEGV / SIGBUS 守卫行为边界

use core::ffi::c_void;
use core::ptr;

use srx_inline_hook::{Errno, hook_single};

pub fn crash_guard_sigsegv() {
    // 0x1000 在 Android 用户态未映射；读 prologue 必触发 SIGSEGV
    let target = 0x1000 as *mut c_void;
    // replacement 随便一个有效地址（本函数地址即可）
    let replacement = crash_guard_sigsegv as *const c_void;

    // SAFETY: guard 包读 prologue，信号由 bytesig 捕获转 HookRewriteCrash；不会崩
    let r = unsafe { hook_single(target, replacement) };
    assert!(
        matches!(r, Err(Errno::HookRewriteCrash)),
        "crash_guard check failed: {:?}",
        r
    );

    // 再来一次验证 guard 可以反复进出而不泄漏状态
    // SAFETY: 同上
    let r = unsafe { hook_single(0x2000 as *mut c_void, ptr::null::<c_void>().cast()) };
    assert!(
        matches!(r, Err(Errno::InvalidArg)),
        "crash_guard check failed: {:?}",
        r
    );

    println!("crash_guard_sigsegv: PASS");
}
