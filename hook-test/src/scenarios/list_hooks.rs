// list_hooks 枚举：install 后条目应包含 target/replacement/tramp_addr
// unhook 后条目应消失；has_orig_slot 与是否传 orig_addr 对齐

use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::sync::atomic::Ordering;

use srx_inline_hook::{hook_with_orig, list_hooks, prev_func, unhook};

use crate::test_ctx::{
    HITS_ADD, HITS_MUL, STUB_ADD, STUB_MUL, clear, install, replacement_add, target_add, target_mul,
};

static mut ORIG_MUL: *const c_void = ptr::null();

extern "C" fn replacement_mul_via_orig(a: i64, b: i64) -> i64 {
    HITS_MUL.fetch_add(1, Ordering::SeqCst);
    // SAFETY: ORIG_MUL 槽在 hook 存活期间持有跳板地址
    let orig = unsafe { ORIG_MUL };
    if orig.is_null() {
        return a.wrapping_mul(b);
    }
    // SAFETY: 跳板 ABI 与 target_mul 一致
    let f: extern "C" fn(i64, i64) -> i64 = unsafe { mem::transmute(orig) };
    f(a, b).wrapping_add(7)
}

// clippy::fn_to_numeric_cast: 函数直转 usize 会告警，先经 *const () 一跳
fn addr_of(f: extern "C" fn(i64, i64) -> i64) -> usize {
    f as *const () as usize
}

pub fn list_hooks_basic() {
    let baseline = list_hooks().len();
    let target_add_addr = addr_of(target_add);
    let target_mul_addr = addr_of(target_mul);
    let replacement_add_addr = addr_of(replacement_add);
    let replacement_mul_addr = addr_of(replacement_mul_via_orig);

    // 第一条：走 hook_single（test_ctx::install），无 orig_slot
    let stub_add = install(&STUB_ADD, target_add, replacement_add);
    // 第二条：走 hook_with_orig，有 orig_slot
    // SAFETY: ORIG_MUL 静态槽在整个 scenario 中存活
    let stub_mul = unsafe {
        hook_with_orig(
            target_mul as *mut c_void,
            replacement_mul_via_orig as *const c_void,
            &raw mut ORIG_MUL,
        )
        .expect("hook_with_orig")
    };
    *STUB_MUL.lock().expect("lock") = Some(stub_mul);

    let entries = list_hooks();
    assert_eq!(entries.len(), baseline + 2, "list_hooks check failed");

    let add_entry = entries
        .iter()
        .find(|e| e.target == target_add_addr)
        .expect("list_hooks check failed");
    assert_eq!(
        add_entry.replacement, replacement_add_addr,
        "list_hooks check failed"
    );
    assert_ne!(add_entry.tramp_addr, 0, "list_hooks check failed");
    assert!(add_entry.consumed > 0, "list_hooks check failed");
    assert!(!add_entry.has_orig_slot, "list_hooks check failed");

    let mul_entry = entries
        .iter()
        .find(|e| e.target == target_mul_addr)
        .expect("list_hooks check failed");
    assert_eq!(
        mul_entry.replacement, replacement_mul_addr,
        "list_hooks check failed"
    );
    assert!(mul_entry.has_orig_slot, "list_hooks check failed");

    // 触发一次，确保 tramp_addr 对应跳板仍可调用
    HITS_ADD.store(0, Ordering::SeqCst);
    HITS_MUL.store(0, Ordering::SeqCst);
    assert_eq!(target_add(3, 4), 1007);
    assert_eq!(target_mul(3, 4), 19);
    assert_eq!(HITS_ADD.load(Ordering::SeqCst), 1);
    assert_eq!(HITS_MUL.load(Ordering::SeqCst), 1);

    // prev_func 返回值应等于 list_hooks 里的 tramp_addr
    // SAFETY: stub 有效
    let prev_add = unsafe { prev_func(stub_add).expect("prev add") };
    assert_eq!(
        prev_add as usize, add_entry.tramp_addr,
        "list_hooks check failed"
    );

    // SAFETY: 两个 stub 均有效
    unsafe { unhook(stub_add).expect("unhook add") };
    unsafe { unhook(stub_mul).expect("unhook mul") };
    clear(&STUB_ADD);
    clear(&STUB_MUL);
    // SAFETY: hook 已解除
    unsafe { ORIG_MUL = ptr::null() };

    let after = list_hooks();
    assert_eq!(after.len(), baseline, "list_hooks check failed");
    assert!(
        after.iter().all(|e| e.target != target_add_addr),
        "list_hooks check failed"
    );
    assert!(
        after.iter().all(|e| e.target != target_mul_addr),
        "list_hooks check failed"
    );

    println!(
        "list_hooks_basic: PASS (baseline={} peak={} final={})",
        baseline,
        baseline + 2,
        after.len()
    );
}
