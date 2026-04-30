// intercept 最小链：按函数地址注册 pre 回调，调用目标时应命中，unintercept 后停止命中

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use srx_inline_hook::{hook_with_orig, unhook};

unsafe extern "C" {
    fn srx_inline_hook_intercept_func_addr(
        func_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_intercept_instr_addr(
        instr_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_unintercept(stub: *mut c_void) -> i32;
    fn srx_inline_hook_get_errno() -> i32;
}

type AddFn = extern "C" fn(i64, i64) -> i64;

#[repr(C)]
struct InterceptCpuContext {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    vregs: [[u64; 2]; 32],
    fpsr: u64,
    fpcr: u64,
}

static PRE_HITS: AtomicUsize = AtomicUsize::new(0);
static HOOK_ORIG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn intercept_target(a: i64, b: i64) -> i64 {
    std::hint::black_box(a).wrapping_add(std::hint::black_box(b))
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl intercept_instr_target",
    ".type intercept_instr_target, @function",
    "intercept_instr_target:",
    "    mov eax, edi",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    add eax, esi",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    ret",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl intercept_instr_target",
    ".type intercept_instr_target, %function",
    "intercept_instr_target:",
    "    mov x9, x0",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    add x0, x9, x1",
    "    ret",
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn intercept_instr_target(a: i32, b: i32) -> i32;
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn intercept_instr_target(a: i64, b: i64) -> i64;
}

extern "C" fn pre_cb(_ctx: *mut c_void, _data: *mut c_void) {
    PRE_HITS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn hook_cb(a: i64, b: i64) -> i64 {
    let orig = HOOK_ORIG.load(Ordering::SeqCst);
    assert!(!orig.is_null(), "intercept_basic check failed");
    let prev: AddFn = unsafe { core::mem::transmute(orig) };
    prev(a, b) + 700
}

#[cfg(target_arch = "x86_64")]
extern "C" fn instr_pre(ctx: *mut c_void, _data: *mut c_void) {
    PRE_HITS.fetch_add(1, Ordering::SeqCst);
    let ctx = ctx as *mut InterceptCpuContext;
    assert!(!ctx.is_null(), "intercept_basic check failed");
    unsafe {
        (*ctx).regs[1] = (*ctx).regs[1].wrapping_add(100);
    }
}

#[cfg(target_arch = "aarch64")]
extern "C" fn instr_pre(ctx: *mut c_void, _data: *mut c_void) {
    PRE_HITS.fetch_add(1, Ordering::SeqCst);
    let ctx = ctx as *mut InterceptCpuContext;
    assert!(!ctx.is_null(), "intercept_basic check failed");
    unsafe {
        assert_ne!((*ctx).pc, 0, "intercept_basic check failed");
        (*ctx).regs[1] = (*ctx).regs[1].wrapping_add(100);
    }
}

pub fn intercept_func_addr_basic() {
    PRE_HITS.store(0, Ordering::SeqCst);

    let stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            intercept_target as *mut c_void,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(!stub.is_null(), "intercept_basic check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_basic check failed"
    );

    let dup = unsafe {
        srx_inline_hook_intercept_func_addr(
            intercept_target as *mut c_void,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(dup.is_null(), "intercept_basic check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        10,
        "intercept_basic check failed"
    );

    let target: extern "C" fn(i64, i64) -> i64 =
        unsafe { core::mem::transmute(intercept_target as *const c_void) };
    assert_eq!(target(3, 4), 7, "intercept_basic check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_basic check failed"
    );

    let mut orig: *const c_void = ptr::null();
    let hook_stub = unsafe {
        hook_with_orig(
            intercept_target as *mut c_void,
            hook_cb as *const c_void,
            &mut orig as *mut *const c_void,
        )
    }
    .expect("intercept_basic check failed");
    HOOK_ORIG.store(orig as *mut c_void, Ordering::SeqCst);
    assert!(!orig.is_null(), "intercept_basic check failed");
    assert_eq!(target(10, 20), 730, "intercept_basic check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        2,
        "intercept_basic check failed"
    );

    unsafe { unhook(hook_stub).expect("intercept_basic check failed") };
    HOOK_ORIG.store(ptr::null_mut(), Ordering::SeqCst);
    assert_eq!(target(5, 6), 11, "intercept_basic check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        3,
        "intercept_basic check failed"
    );

    let rc = unsafe { srx_inline_hook_unintercept(stub) };
    assert_eq!(rc, 0, "intercept_basic check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_basic check failed"
    );

    assert_eq!(target(5, 6), 11, "intercept_basic check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        3,
        "intercept_basic check failed"
    );

    #[cfg(target_arch = "x86_64")]
    {
        PRE_HITS.store(0, Ordering::SeqCst);
        let instr_addr = unsafe { (intercept_instr_target as *const u8).add(5) } as *mut c_void;
        let instr_stub = unsafe {
            srx_inline_hook_intercept_instr_addr(
                instr_addr,
                instr_pre as *mut c_void,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!instr_stub.is_null(), "intercept_basic check failed");
        assert_eq!(
            unsafe { srx_inline_hook_get_errno() },
            0,
            "intercept_basic check failed"
        );
        let value = unsafe { intercept_instr_target(3, 4) };
        assert_eq!(value, 107, "intercept_basic check failed");
        assert_eq!(
            PRE_HITS.load(Ordering::SeqCst),
            1,
            "intercept_basic check failed"
        );
        let instr_rc = unsafe { srx_inline_hook_unintercept(instr_stub) };
        assert_eq!(instr_rc, 0, "intercept_basic check failed");
        let restored = unsafe { intercept_instr_target(3, 4) };
        assert_eq!(restored, 7, "intercept_basic check failed");
    }

    #[cfg(target_arch = "aarch64")]
    {
        PRE_HITS.store(0, Ordering::SeqCst);
        let instr_addr = unsafe { (intercept_instr_target as *const u8).add(4) } as *mut c_void;
        let instr_stub = unsafe {
            srx_inline_hook_intercept_instr_addr(
                instr_addr,
                instr_pre as *mut c_void,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!instr_stub.is_null(), "intercept_basic check failed");
        assert_eq!(
            unsafe { srx_inline_hook_get_errno() },
            0,
            "intercept_basic check failed"
        );
        let value = unsafe { intercept_instr_target(3, 4) };
        assert_eq!(value, 107, "intercept_basic check failed");
        assert_eq!(
            PRE_HITS.load(Ordering::SeqCst),
            1,
            "intercept_basic check failed"
        );
        let instr_rc = unsafe { srx_inline_hook_unintercept(instr_stub) };
        assert_eq!(instr_rc, 0, "intercept_basic check failed");
        let restored = unsafe { intercept_instr_target(3, 4) };
        assert_eq!(restored, 7, "intercept_basic check failed");
    }

    println!("intercept_func_addr_basic: PASS");
}
