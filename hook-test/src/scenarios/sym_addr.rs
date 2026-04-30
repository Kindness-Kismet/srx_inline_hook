// hook_sym_addr 场景：按给定符号地址 hook
// 与 hook_with_orig 等价，差异仅在 RecordOp 标签便于诊断区分

use core::ffi::c_void;
use core::ptr;

use srx_inline_hook::{
    clear_records, dump_records, hook_sym_addr, prev_func, set_recordable, unhook,
};

unsafe extern "C" {
    fn srx_inline_hook_hook_sym_addr_2(
        sym_addr: *mut c_void,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_unhook(stub: *mut c_void) -> i32;
}

use crate::test_ctx::target_add;

extern "C" fn rep(a: i64, b: i64) -> i64 {
    // 走 prev_func 而非全局 STUB，避免与 test_ctx 其他 scenario 交叉污染
    a.wrapping_add(b).wrapping_add(500)
}

pub fn hook_sym_addr_basic() {
    set_recordable(true);
    clear_records();

    assert_eq!(target_add(10, 20), 30);

    // SAFETY: sym_addr / replacement 均为本进程代码地址
    let stub = unsafe {
        hook_sym_addr(
            target_add as *mut c_void,
            rep as *const c_void,
            ptr::null_mut(),
        )
        .expect("hook_sym_addr")
    };
    assert_eq!(target_add(10, 20), 530, "sym_addr check failed");

    // prev_func 仍可访问原语义跳板
    // SAFETY: stub 有效
    let prev = unsafe { prev_func(stub).expect("prev") };
    // SAFETY: ABI 与 target_add 一致
    let prev_fn: extern "C" fn(i64, i64) -> i64 = unsafe { core::mem::transmute(prev) };
    assert_eq!(prev_fn(3, 4), 7, "sym_addr check failed");

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    assert_eq!(target_add(10, 20), 30, "sym_addr check failed");

    let text = dump_records();
    assert!(
        text.contains("hook_sym_addr"),
        "sym_addr check failed: {}",
        text
    );
    assert!(
        !text.contains("hook_func_addr"),
        "sym_addr check failed: {}",
        text
    );
    assert!(
        text.contains(",unknown,") || text.contains(",hook-test,unknown,"),
        "sym_addr check failed: {}",
        text
    );

    clear_records();

    let named_stub = unsafe {
        srx_inline_hook_hook_sym_addr_2(
            target_add as *mut c_void,
            rep as *mut c_void,
            ptr::null_mut(),
            8,
            c"named-hook-lib.so".as_ptr(),
            c"named_add_hook".as_ptr(),
        )
    };
    assert!(!named_stub.is_null(), "sym_addr check failed");
    let named_text = dump_records();
    assert!(
        named_text.contains("named-hook-lib.so") && named_text.contains("named_add_hook"),
        "sym_addr check failed: {}",
        named_text
    );
    let named_unhook = unsafe { srx_inline_hook_unhook(named_stub) };
    assert_eq!(named_unhook, 0, "sym_addr check failed");

    clear_records();
    set_recordable(false);
    println!("hook_sym_addr_basic: PASS");
}
