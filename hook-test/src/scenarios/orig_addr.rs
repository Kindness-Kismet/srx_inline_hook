// hook_with_orig 场景：orig_addr 槽在 hook 激活前写入跳板地址
// replacement 可直接调用该槽，省去 prev_func 查询

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use srx_inline_hook::{HookStub, hook_with_orig, unhook};

use crate::test_ctx::target_mul;

static ORIG_MUL: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// AtomicPtr<c_void> 的内部 layout 与 *const c_void 一致，
// 直接把 .as_ptr() 结果 cast 为 *mut *const c_void 交给 hook_with_orig
fn orig_mul_slot() -> *mut *const c_void {
    ORIG_MUL.as_ptr() as *mut *const c_void
}

extern "C" fn replacement_mul_via_orig(a: i64, b: i64) -> i64 {
    let p = ORIG_MUL.load(Ordering::Acquire);
    if p.is_null() {
        return a.wrapping_mul(b);
    }
    // SAFETY: hook 激活前 orig_addr 已写入；unhook 后清零由库保证
    let orig: extern "C" fn(i64, i64) -> i64 = unsafe { core::mem::transmute(p) };
    orig(a, b).wrapping_add(7)
}

pub fn hook_with_orig_basic() {
    assert!(
        ORIG_MUL.load(Ordering::SeqCst).is_null(),
        "orig_addr check failed"
    );
    assert_eq!(target_mul(6, 7), 42);

    // SAFETY: target 与 replacement 为本进程可执行地址；slot 指向 'static AtomicPtr
    let stub: HookStub = unsafe {
        hook_with_orig(
            target_mul as *mut c_void,
            replacement_mul_via_orig as *const c_void,
            orig_mul_slot(),
        )
        .expect("hook_with_orig")
    };
    assert!(
        !ORIG_MUL.load(Ordering::SeqCst).is_null(),
        "orig_addr check failed"
    );

    assert_eq!(target_mul(6, 7), 49, "orig_addr check failed");

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    assert!(
        ORIG_MUL.load(Ordering::SeqCst).is_null(),
        "orig_addr check failed"
    );
    assert_eq!(target_mul(6, 7), 42, "orig_addr check failed");
    println!("hook_with_orig_basic: PASS");
}
