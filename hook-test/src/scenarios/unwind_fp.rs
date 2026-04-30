// FP unwind：在 hook proxy 与 intercept pre 中抓 backtrace
// 目标：调用栈应稳定回到本 scenario 的 probe 函数

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use core::arch::global_asm;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use srx_inline_hook::{HookStub, hook_with_orig, unhook};

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.globl srx_current_frame_pointer_x86_64
.balign 16
.type srx_current_frame_pointer_x86_64, @function
srx_current_frame_pointer_x86_64:
    mov rax, rbp
    ret
.size srx_current_frame_pointer_x86_64, .-srx_current_frame_pointer_x86_64
"#
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.globl srx_current_frame_pointer_aarch64
.balign 4
.type srx_current_frame_pointer_aarch64, %function
srx_current_frame_pointer_aarch64:
    mov x0, x29
    ret
.size srx_current_frame_pointer_aarch64, .-srx_current_frame_pointer_aarch64
"#
);

unsafe extern "C" {
    fn _Unwind_FindEnclosingFunction(pc: *mut c_void) -> *mut c_void;
    #[cfg(target_arch = "x86_64")]
    fn srx_current_frame_pointer_x86_64() -> *const usize;
    #[cfg(target_arch = "aarch64")]
    fn srx_current_frame_pointer_aarch64() -> *const usize;
    fn srx_inline_hook_intercept_func_addr(
        func_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_unintercept(stub: *mut c_void) -> i32;
}

static mut ORIG_UNWIND: *const c_void = core::ptr::null();
static HOOK_BT_HITS: AtomicUsize = AtomicUsize::new(0);
static INTERCEPT_BT_HITS: AtomicUsize = AtomicUsize::new(0);
static HOOK_SAW_PROBE: AtomicBool = AtomicBool::new(false);
static INTERCEPT_SAW_PROBE: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn unwind_target(a: i64, b: i64) -> i64 {
    std::hint::black_box(a).wrapping_add(std::hint::black_box(b))
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn unwind_fp_hook_probe(a: i64, b: i64) -> i64 {
    let result = unwind_target(a, b);
    std::hint::black_box(a);
    result
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn unwind_fp_intercept_probe(a: i64, b: i64) -> i64 {
    let result = unwind_target(a, b);
    std::hint::black_box(b);
    result
}

fn capture_backtrace_contains_symbol(sym_addr: *const c_void) -> bool {
    capture_fp_backtrace()
        .into_iter()
        .any(|pc| pc_matches_symbol(pc, sym_addr))
}

fn capture_fp_backtrace() -> Vec<usize> {
    let mut frames = Vec::with_capacity(64);
    let mut frame = current_frame_pointer();
    let mut last = 0usize;
    while !frame.is_null() && frames.len() < 64 {
        let frame_addr = frame as usize;
        if frame_addr <= last || (frame_addr & (core::mem::size_of::<usize>() - 1)) != 0 {
            break;
        }
        let ret = unsafe { *frame.add(1) };
        if ret == 0 {
            break;
        }
        frames.push(ret);
        let next = unsafe { *frame } as *const usize;
        if next.is_null() || next as usize <= frame_addr {
            break;
        }
        last = frame_addr;
        frame = next;
    }
    frames
}

fn current_frame_pointer() -> *const usize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        srx_current_frame_pointer_x86_64()
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        srx_current_frame_pointer_aarch64()
    }
}

fn pc_matches_symbol(pc: usize, sym_addr: *const c_void) -> bool {
    if pc == 0 {
        return false;
    }
    enclosing_fn_addr(pc as *const c_void) == sym_addr
        || enclosing_fn_addr(pc.wrapping_sub(1) as *const c_void) == sym_addr
}

fn enclosing_fn_addr(pc: *const c_void) -> *const c_void {
    unsafe { _Unwind_FindEnclosingFunction(pc as *mut c_void) as *const c_void }
}

extern "C" fn unwind_hook_replacement(a: i64, b: i64) -> i64 {
    HOOK_BT_HITS.fetch_add(1, Ordering::SeqCst);
    let saw_probe = capture_backtrace_contains_symbol(unwind_fp_hook_probe as *const c_void);
    HOOK_SAW_PROBE.store(saw_probe, Ordering::SeqCst);
    let orig: extern "C" fn(i64, i64) -> i64 = unsafe { core::mem::transmute(ORIG_UNWIND) };
    orig(a, b) + 100
}

extern "C" fn unwind_intercept_pre(_ctx: *mut c_void, _data: *mut c_void) {
    INTERCEPT_BT_HITS.fetch_add(1, Ordering::SeqCst);
    let saw_probe = capture_backtrace_contains_symbol(unwind_fp_intercept_probe as *const c_void);
    INTERCEPT_SAW_PROBE.store(saw_probe, Ordering::SeqCst);
}

pub fn fp_unwind_basic() {
    HOOK_BT_HITS.store(0, Ordering::SeqCst);
    INTERCEPT_BT_HITS.store(0, Ordering::SeqCst);
    HOOK_SAW_PROBE.store(false, Ordering::SeqCst);
    INTERCEPT_SAW_PROBE.store(false, Ordering::SeqCst);
    unsafe { ORIG_UNWIND = core::ptr::null() };

    assert_eq!(
        enclosing_fn_addr(unwind_fp_hook_probe as *const c_void),
        unwind_fp_hook_probe as *const c_void,
        "unwind_fp check failed"
    );
    assert_eq!(
        enclosing_fn_addr(unwind_fp_intercept_probe as *const c_void),
        unwind_fp_intercept_probe as *const c_void,
        "unwind_fp check failed"
    );

    let hook_stub: HookStub = unsafe {
        hook_with_orig(
            unwind_target as *mut c_void,
            unwind_hook_replacement as *const c_void,
            core::ptr::addr_of_mut!(ORIG_UNWIND),
        )
        .expect("install unwind hook")
    };
    assert_eq!(unwind_fp_hook_probe(3, 4), 107, "unwind_fp check failed");
    assert_eq!(
        HOOK_BT_HITS.load(Ordering::SeqCst),
        1,
        "unwind_fp check failed"
    );
    assert!(
        HOOK_SAW_PROBE.load(Ordering::SeqCst),
        "unwind_fp check failed"
    );
    unsafe { unhook(hook_stub).expect("unhook unwind hook") };

    let intercept_stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            unwind_target as *mut c_void,
            unwind_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(!intercept_stub.is_null(), "install unwind intercept");
    assert_eq!(
        unwind_fp_intercept_probe(8, 9),
        17,
        "unwind_fp check failed"
    );
    assert_eq!(
        INTERCEPT_BT_HITS.load(Ordering::SeqCst),
        1,
        "unwind_fp check failed"
    );
    assert!(
        INTERCEPT_SAW_PROBE.load(Ordering::SeqCst),
        "unwind_fp check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_unintercept(intercept_stub) },
        0,
        "unwind_fp check failed"
    );

    println!("fp_unwind_basic: PASS");
}
