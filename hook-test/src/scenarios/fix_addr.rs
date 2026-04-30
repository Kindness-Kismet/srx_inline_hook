// 验证 prologue 内部相对跳转能重定位到 trampoline 对应偏移
// arm64 覆盖 CBZ，x86_64 覆盖 JNZ rel8

use core::ffi::c_void;
use std::sync::Mutex;

use srx_inline_hook::{HookStub, hook_single, prev_func, unhook};

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl target_fix_addr_branch",
    ".type target_fix_addr_branch, %function",
    "target_fix_addr_branch:",
    "    cbz x0, 1f",
    "    mov x0, #7",
    "    b 2f",
    "1:  mov x0, #42",
    "2:  ret",
);

// x86_64 prologue 内含 JNZ 到 RET，重写后必须映射到 trampoline 内
// rdi==0 返回 42；rdi!=0 返回 7
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl target_fix_addr_branch",
    ".type target_fix_addr_branch, @function",
    "target_fix_addr_branch:",
    "    mov eax, 7",
    "    test edi, edi",
    "    jnz 1f",
    "    mov al, 42",
    "    nop",
    "    nop",
    "1:  ret",
);

unsafe extern "C" {
    fn target_fix_addr_branch(x: u64) -> u64;
}

static STUB_FIX: Mutex<Option<HookStub>> = Mutex::new(None);

extern "C" fn replacement_fix_addr(x: u64) -> u64 {
    let stub = STUB_FIX.lock().expect("lock fix").expect("stub fix");
    // SAFETY: hook 期间 stub 有效
    let prev = unsafe { prev_func(stub).expect("prev fix") };
    // SAFETY: trampoline ABI 与原函数一致
    let prev_fn: extern "C" fn(u64) -> u64 = unsafe { core::mem::transmute(prev) };
    prev_fn(x).wrapping_add(1000)
}

pub fn fix_addr_internal_branch() {
    // SAFETY: target_fix_addr_branch 为 'static 函数符号
    let before_zero = unsafe { target_fix_addr_branch(0) };
    assert_eq!(before_zero, 42, "fix_addr check failed");
    // SAFETY: 同上
    let before_one = unsafe { target_fix_addr_branch(1) };
    assert_eq!(before_one, 7, "fix_addr check failed");

    // SAFETY: 目标为本进程函数指针；replacement 为 extern "C"
    let stub = unsafe {
        hook_single(
            target_fix_addr_branch as *mut c_void,
            replacement_fix_addr as *const c_void,
        )
        .expect("hook fix")
    };
    *STUB_FIX.lock().expect("lock fix") = Some(stub);

    // hook 后：走 replacement → prev_func → 原始语义 + 1000
    // SAFETY: hook 已装
    let after_zero = unsafe { target_fix_addr_branch(0) };
    assert_eq!(after_zero, 1042, "fix_addr check failed");
    // SAFETY: 同上
    let after_one = unsafe { target_fix_addr_branch(1) };
    assert_eq!(after_one, 1007, "fix_addr check failed");

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook fix") };
    *STUB_FIX.lock().expect("lock fix") = None;

    // 恢复后再验一次：prologue 已完整回写、内部跳转仍生效
    // SAFETY: 已 unhook
    let restored_zero = unsafe { target_fix_addr_branch(0) };
    assert_eq!(restored_zero, 42);
    // SAFETY: 同上
    let restored_one = unsafe { target_fix_addr_branch(1) };
    assert_eq!(restored_one, 7);
    println!("fix_addr_internal_branch: PASS");
}
