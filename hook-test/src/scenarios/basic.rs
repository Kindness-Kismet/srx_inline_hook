// 基础场景：hook / unhook / 去重 / 重复卸载 / 再 hook

use core::ffi::c_void;
use std::sync::atomic::Ordering;

use srx_inline_hook::{Errno, hook_single, unhook};

use crate::test_ctx::{
    HITS_ADD, HITS_MUL, STUB_ADD, STUB_MUL, clear, install, replacement_add, replacement_mul,
    target_add, target_mul,
};

pub fn basic() {
    HITS_ADD.store(0, Ordering::SeqCst);
    let before = target_add(3, 4);
    assert_eq!(before, 7);

    let stub = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(target_add(3, 4), 1007);
    assert_eq!(HITS_ADD.load(Ordering::SeqCst), 1);

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);
    assert_eq!(target_add(3, 4), 7);
    println!("basic: PASS");
}

pub fn multi_hook() {
    HITS_ADD.store(0, Ordering::SeqCst);
    HITS_MUL.store(0, Ordering::SeqCst);

    let s_add = install(&STUB_ADD, target_add, replacement_add);
    let s_mul = install(&STUB_MUL, target_mul, replacement_mul);

    assert_eq!(target_add(10, 20), 1030);
    assert_eq!(target_mul(3, 4), 14);
    assert_eq!(HITS_ADD.load(Ordering::SeqCst), 1);
    assert_eq!(HITS_MUL.load(Ordering::SeqCst), 1);

    // SAFETY: 两个 stub 均有效
    unsafe {
        unhook(s_add).expect("unhook add");
        unhook(s_mul).expect("unhook mul");
    }
    clear(&STUB_ADD);
    clear(&STUB_MUL);

    assert_eq!(target_add(10, 20), 30);
    assert_eq!(target_mul(3, 4), 12);
    println!("multi_hook: PASS");
}

pub fn duplicate_hook() {
    let stub = install(&STUB_ADD, target_add, replacement_add);
    // SAFETY: 第二次 hook 同地址在 UNIQUE 模式下应返回 HookUniqueDup
    let again = unsafe { hook_single(target_add as *mut c_void, replacement_add as *const c_void) };
    assert!(matches!(again, Err(Errno::HookUniqueDup)));

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);
    println!("duplicate_hook: PASS");
}

pub fn unhook_missing() {
    let stub = install(&STUB_ADD, target_add, replacement_add);
    // SAFETY: 首次 unhook 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);
    // SAFETY: 第二次 unhook 同 stub 应返回 UnhookNotFound
    let again = unsafe { unhook(stub) };
    assert!(matches!(again, Err(Errno::UnhookNotFound)));
    println!("unhook_missing: PASS");
}

pub fn rehook_after_unhook() {
    let s1 = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(target_add(1, 1), 1002);
    // SAFETY: s1 有效
    unsafe { unhook(s1).expect("unhook1") };
    clear(&STUB_ADD);
    assert_eq!(target_add(1, 1), 2);

    let s2 = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(target_add(1, 1), 1002);
    // SAFETY: s2 有效
    unsafe { unhook(s2).expect("unhook2") };
    clear(&STUB_ADD);
    println!("rehook_after_unhook: PASS");
}
