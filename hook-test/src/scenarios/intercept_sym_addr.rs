// intercept_sym_addr 最小链：按符号地址注册 pre 回调，调用目标时应命中
// 与 intercept_func_addr 的差异只在 API 入口与记录标签

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    fn srx_inline_hook_intercept_sym_addr(
        sym_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_unintercept(stub: *mut c_void) -> c_int;
    fn srx_inline_hook_get_errno() -> c_int;
}

const INTERCEPT_FPSIMD_READ_ONLY: u32 = 1;
const INTERCEPT_FPSIMD_WRITE_ONLY: u32 = 2;
const INTERCEPT_FPSIMD_READ_WRITE: u32 = 3;
const INTERCEPT_RECORD: u32 = 4;

type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;

static PRE_HITS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn pre_cb(_ctx: *mut c_void, _data: *mut c_void) {
    PRE_HITS.fetch_add(1, Ordering::SeqCst);
}

pub fn intercept_sym_addr_basic() {
    PRE_HITS.store(0, Ordering::SeqCst);

    let handle = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        println!("intercept_sym_addr_basic: skipped");
        return;
    }
    let strlen_ptr = unsafe { libc::dlsym(handle, c"strlen".as_ptr()) };
    if strlen_ptr.is_null() {
        println!("intercept_sym_addr_basic: skipped");
        return;
    }
    let strlen_fn: StrlenFn = unsafe { core::mem::transmute(strlen_ptr) };

    let bad_flags = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            0x100,
        )
    };
    assert!(bad_flags.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_sym_addr check failed"
    );

    let stub = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(!stub.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_sym_addr check failed"
    );

    let dup = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(dup.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        10,
        "intercept_sym_addr check failed"
    );

    let probe = c"intercept-sym-addr";
    let len = unsafe { strlen_fn(probe.as_ptr()) };
    assert_eq!(len, 18, "intercept_sym_addr check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_addr check failed"
    );

    let rc = unsafe { srx_inline_hook_unintercept(stub) };
    assert_eq!(rc, 0, "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_sym_addr check failed"
    );

    let len2 = unsafe { strlen_fn(c"abc".as_ptr()) };
    assert_eq!(len2, 3, "intercept_sym_addr check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_addr check failed"
    );

    let bad_record_lib = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_RECORD,
            c"bad lib.so".as_ptr(),
            c"named_strlen".as_ptr(),
        )
    };
    assert!(bad_record_lib.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_sym_addr check failed"
    );

    let bad_record_sym = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_RECORD,
            c"named-lib.so".as_ptr(),
            c"bad sym".as_ptr(),
        )
    };
    assert!(bad_record_sym.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_sym_addr check failed"
    );

    let ro_stub = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_FPSIMD_READ_ONLY | INTERCEPT_RECORD,
            c"named-lib.so".as_ptr(),
            c"named_strlen".as_ptr(),
        )
    };
    assert!(!ro_stub.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_sym_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_unintercept(ro_stub) },
        0,
        "intercept_sym_addr check failed"
    );

    let rw_stub = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_FPSIMD_READ_WRITE,
        )
    };
    assert!(!rw_stub.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_sym_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_unintercept(rw_stub) },
        0,
        "intercept_sym_addr check failed"
    );

    let wo_stub = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            pre_cb as *mut c_void,
            core::ptr::null_mut(),
            INTERCEPT_FPSIMD_WRITE_ONLY,
        )
    };
    assert!(!wo_stub.is_null(), "intercept_sym_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_sym_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_unintercept(wo_stub) },
        0,
        "intercept_sym_addr check failed"
    );

    println!("intercept_sym_addr_basic: PASS");
}
