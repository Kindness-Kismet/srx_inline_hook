// MULTI 模式链式调用：2+ proxy 叠加，验证 orig_slot 自动 rewire 与 unhook 拆链逻辑

use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::hint;

use srx_inline_hook::{hook_multi, unhook};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn multi_target(x: i64) -> i64 {
    hint::black_box(x) + 100
}

static ORIG_A: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIG_B: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// 链的下一环：单 proxy 时是 tramp→原函数；双 proxy 时 rewire 后指向 proxy_b
extern "C" fn proxy_a(x: i64) -> i64 {
    let next = ORIG_A.load(Ordering::Acquire);
    // SAFETY: next 由 hook_multi / push_multi 写入，ABI 与 target 一致
    let f: extern "C" fn(i64) -> i64 = unsafe { mem::transmute(next) };
    f(x) + 10
}

extern "C" fn proxy_b(x: i64) -> i64 {
    let next = ORIG_B.load(Ordering::Acquire);
    // SAFETY: 同 proxy_a
    let f: extern "C" fn(i64) -> i64 = unsafe { mem::transmute(next) };
    f(x) * 2
}

pub fn multi_chain_basic() {
    assert_eq!(multi_target(5), 105);

    // 首个 proxy：target→proxy_a→tramp→原 → proxy_a +10 → 115
    let slot_a = ORIG_A.as_ptr() as *mut *const c_void;
    // SAFETY: multi_target / proxy_a 为本进程可执行代码；slot_a 为 AtomicPtr 内部存储地址
    let stub_a = unsafe {
        hook_multi(
            multi_target as *mut c_void,
            proxy_a as *const c_void,
            slot_a,
        )
        .expect("hook_multi a")
    };
    assert_eq!(multi_target(5), 115, "multi_chain check failed");

    // 追加第二个 proxy：patch 不动，proxy_a.orig rewire → proxy_b，proxy_b.orig → tramp
    let slot_b = ORIG_B.as_ptr() as *mut *const c_void;
    // SAFETY: 同上
    let stub_b = unsafe {
        hook_multi(
            multi_target as *mut c_void,
            proxy_b as *const c_void,
            slot_b,
        )
        .expect("hook_multi b")
    };
    // 链：target→proxy_a→proxy_b→tramp→原 105；proxy_b: 210；proxy_a: 220
    assert_eq!(multi_target(5), 220, "multi_chain check failed");

    // 拆 proxy_b（非 head）：proxy_a.orig 应 rewire 回 tramp
    // SAFETY: stub_b 有效
    unsafe { unhook(stub_b).expect("unhook b") };
    assert_eq!(multi_target(5), 115, "multi_chain check failed");

    // 拆 proxy_a（head，queue 空）：patch 还原 original
    // SAFETY: stub_a 有效
    unsafe { unhook(stub_a).expect("unhook a") };
    assert_eq!(multi_target(5), 105, "multi_chain check failed");

    println!("multi_chain_basic: PASS");
}
