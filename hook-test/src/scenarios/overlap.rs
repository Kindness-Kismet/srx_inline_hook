// overlap 防踩踏：两个紧邻函数的 patch 区间相交时 HookOverlap 拦截
// layout：neighbor_a 占 12B，neighbor_b 紧接 a+12；hook a 后 hook b 必然相交

use core::ffi::c_void;

use srx_inline_hook::{Errno, hook_single, unhook};

core::arch::global_asm!(
    ".globl neighbor_a",
    ".type neighbor_a, %function",
    "neighbor_a:",
    "    mov x0, #11",
    "    mov x1, #22",
    "    ret",
    ".globl neighbor_b",
    ".type neighbor_b, %function",
    "neighbor_b:",
    "    mov x0, #33",
    "    mov x1, #44",
    "    ret",
    "    nop",
    "    nop",
    "    nop",
);

unsafe extern "C" {
    fn neighbor_a() -> i64;
    fn neighbor_b() -> i64;
}

extern "C" fn dummy_replacement() -> i64 {
    0
}

pub fn hook_overlap_rejection() {
    // SAFETY: neighbor_a 为 'static 代码地址；replacement 对齐签名
    let stub_a = unsafe {
        hook_single(
            neighbor_a as *mut c_void,
            dummy_replacement as *const c_void,
        )
        .expect("hook neighbor_a")
    };

    // neighbor_b 位于 a+12，与 [a, a+16) 相交 4 字节
    // SAFETY: 尝试 hook neighbor_b 应被 has_overlap 拦下
    let r = unsafe {
        hook_single(
            neighbor_b as *mut c_void,
            dummy_replacement as *const c_void,
        )
    };
    assert!(
        matches!(r, Err(Errno::HookOverlap)),
        "overlap check failed: {:?}",
        r
    );

    // SAFETY: stub_a 有效
    unsafe { unhook(stub_a).expect("unhook neighbor_a") };
    println!("hook_overlap_rejection: PASS");
}
