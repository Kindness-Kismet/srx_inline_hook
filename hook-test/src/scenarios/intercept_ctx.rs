// intercept CPU context：x86_64 下验证前 6 个整数参数；aarch64 再验证最小 FPSIMD 读写
// pre 回调改写通用整参后，原函数应看到新值

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SrxInlineHookVReg {
    d: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SrxInlineHookCpuContext {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    vregs: [SrxInlineHookVReg; 32],
    fpsr: u64,
    fpcr: u64,
}

unsafe extern "C" {
    fn srx_inline_hook_intercept_func_addr(
        func_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_unintercept(stub: *mut c_void) -> i32;
    fn srx_inline_hook_get_errno() -> i32;
}

const INTERCEPT_FPSIMD_READ_ONLY: u32 = 1;
const INTERCEPT_FPSIMD_WRITE_ONLY: u32 = 2;
const INTERCEPT_FPSIMD_READ_WRITE: u32 = 3;
const INTERCEPT_RECORD: u32 = 4;

static SEEN_PC: AtomicU64 = AtomicU64::new(0);
static SEEN_SP: AtomicU64 = AtomicU64::new(0);
static SEEN_A0: AtomicU64 = AtomicU64::new(0);
static SEEN_A1: AtomicU64 = AtomicU64::new(0);
static SEEN_A2: AtomicU64 = AtomicU64::new(0);
static SEEN_A3: AtomicU64 = AtomicU64::new(0);
static SEEN_A4: AtomicU64 = AtomicU64::new(0);
static SEEN_A5: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_Q0_LO: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_Q0_HI: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_FPSR: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static SEEN_FPCR: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn ctx_target(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    std::hint::black_box(a0)
        .wrapping_add(std::hint::black_box(a1))
        .wrapping_add(std::hint::black_box(a2))
        .wrapping_add(std::hint::black_box(a3))
        .wrapping_add(std::hint::black_box(a4))
        .wrapping_add(std::hint::black_box(a5))
}

#[cfg(target_arch = "x86_64")]
extern "C" fn pre_cb(ctx: *mut c_void, _data: *mut c_void) {
    let ctx = unsafe { &mut *(ctx as *mut SrxInlineHookCpuContext) };
    SEEN_PC.store(ctx.pc, Ordering::SeqCst);
    SEEN_SP.store(ctx.sp, Ordering::SeqCst);
    SEEN_A0.store(ctx.regs[0], Ordering::SeqCst);
    SEEN_A1.store(ctx.regs[1], Ordering::SeqCst);
    SEEN_A2.store(ctx.regs[2], Ordering::SeqCst);
    SEEN_A3.store(ctx.regs[3], Ordering::SeqCst);
    SEEN_A4.store(ctx.regs[4], Ordering::SeqCst);
    SEEN_A5.store(ctx.regs[5], Ordering::SeqCst);
    ctx.regs[0] = 10;
    ctx.regs[1] = 20;
}

#[cfg(target_arch = "aarch64")]
extern "C" fn pre_cb(ctx: *mut c_void, _data: *mut c_void) {
    let ctx = unsafe { &mut *(ctx as *mut SrxInlineHookCpuContext) };
    SEEN_PC.store(ctx.pc, Ordering::SeqCst);
    SEEN_SP.store(ctx.sp, Ordering::SeqCst);
    SEEN_A0.store(ctx.regs[0], Ordering::SeqCst);
    SEEN_A1.store(ctx.regs[1], Ordering::SeqCst);
    SEEN_A2.store(ctx.regs[2], Ordering::SeqCst);
    SEEN_A3.store(ctx.regs[3], Ordering::SeqCst);
    SEEN_A4.store(ctx.regs[4], Ordering::SeqCst);
    SEEN_A5.store(ctx.regs[5], Ordering::SeqCst);
    SEEN_Q0_LO.store(ctx.vregs[0].d[0], Ordering::SeqCst);
    SEEN_Q0_HI.store(ctx.vregs[0].d[1], Ordering::SeqCst);
    SEEN_FPSR.store(ctx.fpsr, Ordering::SeqCst);
    SEEN_FPCR.store(ctx.fpcr, Ordering::SeqCst);
    ctx.regs[0] = 10;
    ctx.regs[1] = 20;
    ctx.vregs[0].d = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00];
    ctx.fpsr = 0x10;
    ctx.fpcr = 0;
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn arm64_ctx_target(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64;
    fn arm64_ctx_call_target() -> u64;
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl arm64_ctx_call_target",
    ".type arm64_ctx_call_target, %function",
    "arm64_ctx_call_target:",
    "    stp x29, x30, [sp, #-16]!",
    "    mov x29, sp",
    "    mov x9, #0x1234",
    "    movk x9, #0x5678, lsl #16",
    "    movk x9, #0x9abc, lsl #32",
    "    movk x9, #0xdef0, lsl #48",
    "    fmov d0, x9",
    "    mov x10, #0x0fed",
    "    movk x10, #0xcba9, lsl #16",
    "    movk x10, #0x8765, lsl #32",
    "    movk x10, #0x4321, lsl #48",
    "    fmov v0.d[1], x10",
    "    mov x11, #0x11",
    "    msr fpsr, x11",
    "    mov x12, #0x22",
    "    msr fpcr, x12",
    "    mov x0, #1",
    "    mov x1, #2",
    "    mov x2, #3",
    "    mov x3, #4",
    "    mov x4, #5",
    "    mov x5, #6",
    "    bl arm64_ctx_target",
    "    mov x9, #0x7788",
    "    movk x9, #0x5566, lsl #16",
    "    movk x9, #0x3344, lsl #32",
    "    movk x9, #0x1122, lsl #48",
    "    fmov x10, d0",
    "    cmp x10, x9",
    "    cset x11, eq",
    "    mov x9, #0xff00",
    "    movk x9, #0xddee, lsl #16",
    "    movk x9, #0xbbcc, lsl #32",
    "    movk x9, #0x99aa, lsl #48",
    "    fmov x10, v0.d[1]",
    "    cmp x10, x9",
    "    cinc x11, x11, eq",
    "    mrs x10, fpsr",
    "    cmp x10, #0x10",
    "    cinc x11, x11, eq",
    "    mrs x10, fpcr",
    "    cmp x10, #0",
    "    cinc x11, x11, eq",
    "    add x0, x0, x11",
    "    ldp x29, x30, [sp], #16",
    "    ret",
    ".globl arm64_ctx_target",
    ".type arm64_ctx_target, %function",
    "arm64_ctx_target:",
    "    add x0, x0, x1",
    "    add x0, x0, x2",
    "    add x0, x0, x3",
    "    add x0, x0, x4",
    "    add x0, x0, x5",
    "    ret",
);

pub fn intercept_cpu_context_basic() {
    SEEN_PC.store(0, Ordering::SeqCst);
    SEEN_SP.store(0, Ordering::SeqCst);
    SEEN_A0.store(0, Ordering::SeqCst);
    SEEN_A1.store(0, Ordering::SeqCst);
    SEEN_A2.store(0, Ordering::SeqCst);
    SEEN_A3.store(0, Ordering::SeqCst);
    SEEN_A4.store(0, Ordering::SeqCst);
    SEEN_A5.store(0, Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    {
        SEEN_Q0_LO.store(0, Ordering::SeqCst);
        SEEN_Q0_HI.store(0, Ordering::SeqCst);
        SEEN_FPSR.store(0, Ordering::SeqCst);
        SEEN_FPCR.store(0, Ordering::SeqCst);
    }

    #[cfg(target_arch = "x86_64")]
    let target_addr = ctx_target as *mut c_void;
    #[cfg(target_arch = "aarch64")]
    let target_addr = arm64_ctx_target as *mut c_void;

    let stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            target_addr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_FPSIMD_READ_WRITE,
        )
    };
    assert!(!stub.is_null(), "intercept_ctx check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_ctx check failed"
    );

    #[cfg(target_arch = "x86_64")]
    let target: extern "C" fn(u64, u64, u64, u64, u64, u64) -> u64 =
        unsafe { core::mem::transmute(ctx_target as *const c_void) };

    #[cfg(target_arch = "x86_64")]
    let v = target(1, 2, 3, 4, 5, 6);
    #[cfg(target_arch = "aarch64")]
    let v = unsafe { arm64_ctx_call_target() };
    #[cfg(target_arch = "x86_64")]
    assert_eq!(v, 48, "intercept_ctx check failed");
    #[cfg(target_arch = "aarch64")]
    assert_eq!(v, 52, "intercept_ctx check failed");
    assert_eq!(
        SEEN_PC.load(Ordering::SeqCst),
        target_addr as usize as u64,
        "intercept_ctx check failed"
    );
    assert_ne!(
        SEEN_SP.load(Ordering::SeqCst),
        0,
        "intercept_ctx check failed"
    );
    assert_eq!(
        SEEN_A0.load(Ordering::SeqCst),
        1,
        "intercept_ctx check failed"
    );
    assert_eq!(
        SEEN_A1.load(Ordering::SeqCst),
        2,
        "intercept_ctx check failed"
    );
    assert_eq!(
        SEEN_A2.load(Ordering::SeqCst),
        3,
        "intercept_ctx check failed"
    );
    assert_eq!(
        SEEN_A3.load(Ordering::SeqCst),
        4,
        "intercept_ctx check failed"
    );
    assert_eq!(
        SEEN_A4.load(Ordering::SeqCst),
        5,
        "intercept_ctx check failed"
    );
    assert_eq!(
        SEEN_A5.load(Ordering::SeqCst),
        6,
        "intercept_ctx check failed"
    );

    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(SEEN_Q0_LO.load(Ordering::SeqCst), 0xdef0_9abc_5678_1234);
        assert_eq!(SEEN_Q0_HI.load(Ordering::SeqCst), 0x4321_8765_cba9_0fed);
        assert_eq!(SEEN_FPSR.load(Ordering::SeqCst), 0x11);
        assert_eq!(SEEN_FPCR.load(Ordering::SeqCst), 0);
    }

    let rc = unsafe { srx_inline_hook_unintercept(stub) };
    assert_eq!(rc, 0, "intercept_ctx check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_ctx check failed"
    );

    #[cfg(target_arch = "x86_64")]
    let restored = target(1, 2, 3, 4, 5, 6);
    #[cfg(target_arch = "aarch64")]
    let restored = unsafe { arm64_ctx_call_target() };
    #[cfg(target_arch = "x86_64")]
    assert_eq!(restored, 21, "intercept_ctx check failed");
    #[cfg(target_arch = "aarch64")]
    assert_eq!(restored, 22, "intercept_ctx check failed");

    let bad_record_lib = unsafe {
        srx_inline_hook_intercept_func_addr(
            target_addr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_RECORD,
            c"bad lib.so".as_ptr(),
            c"intercept_cpu_context_basic".as_ptr(),
        )
    };
    assert!(bad_record_lib.is_null(), "intercept_ctx check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_ctx check failed"
    );

    let bad_record_sym = unsafe {
        srx_inline_hook_intercept_func_addr(
            target_addr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_RECORD,
            c"ctx-target".as_ptr(),
            c"bad sym".as_ptr(),
        )
    };
    assert!(bad_record_sym.is_null(), "intercept_ctx check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_ctx check failed"
    );

    let flags_stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            target_addr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_FPSIMD_READ_ONLY | INTERCEPT_RECORD,
            c"ctx-target".as_ptr(),
            c"intercept_cpu_context_basic".as_ptr(),
        )
    };
    assert!(!flags_stub.is_null(), "intercept_ctx check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_ctx check failed"
    );
    let flags_unhook = unsafe { srx_inline_hook_unintercept(flags_stub) };
    assert_eq!(flags_unhook, 0, "intercept_ctx check failed");

    let rw_stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            target_addr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_FPSIMD_READ_WRITE,
        )
    };
    assert!(!rw_stub.is_null(), "intercept_ctx check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_ctx check failed"
    );
    let rw_unhook = unsafe { srx_inline_hook_unintercept(rw_stub) };
    assert_eq!(rw_unhook, 0, "intercept_ctx check failed");

    let wo_stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            target_addr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_FPSIMD_WRITE_ONLY,
        )
    };
    assert!(!wo_stub.is_null(), "intercept_ctx check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_ctx check failed"
    );
    let wo_unhook = unsafe { srx_inline_hook_unintercept(wo_stub) };
    assert_eq!(wo_unhook, 0, "intercept_ctx check failed");

    println!("intercept_cpu_context_basic: PASS");
}
