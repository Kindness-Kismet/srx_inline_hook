// pending reopen：已完成 pending hook 在 dlclose 后应复位，后续再 dlopen 能重新自动补装

use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};

use srx_inline_hook::{Errno, get_errno, hook_sym_name, hook_sym_name_callback, unhook};

type AddFn = unsafe extern "C" fn(c_int, c_int) -> c_int;

static ORIG_ADD: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CALLBACK_HITS: AtomicU32 = AtomicU32::new(0);
static CALLBACK_ERR: AtomicI32 = AtomicI32::new(-1);
static CALLBACK_SYM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

fn orig_add_slot() -> *mut *const c_void {
    ORIG_ADD.as_ptr() as *mut *const c_void
}

extern "C" fn replacement_add(a: c_int, b: c_int) -> c_int {
    let p = ORIG_ADD.load(Ordering::Acquire);
    if p.is_null() {
        return -1;
    }
    // SAFETY: 自动补装成功后 orig 槽指向 trampoline
    let orig: AddFn = unsafe { core::mem::transmute(p) };
    // SAFETY: ABI 与导出函数一致
    unsafe { orig(a, b) + 2000 }
}

extern "C" fn reopen_hooked_cb(
    error: c_int,
    _lib: *const core::ffi::c_char,
    _sym: *const core::ffi::c_char,
    sym_addr: *const c_void,
    _new: *const c_void,
    _orig: *const c_void,
    _arg: *mut c_void,
) {
    CALLBACK_HITS.fetch_add(1, Ordering::SeqCst);
    CALLBACK_ERR.store(error, Ordering::SeqCst);
    CALLBACK_SYM.store(sym_addr as *mut c_void, Ordering::SeqCst);
}

pub fn pending_reopen_basic() {
    ORIG_ADD.store(ptr::null_mut(), Ordering::SeqCst);

    // SAFETY: 初次调用时目标 so 未加载，返回 pending 句柄
    let stub = unsafe {
        hook_sym_name(
            c"libctor_dtor_probe.so",
            c"ctor_dtor_probe_add",
            replacement_add as *const c_void,
            orig_add_slot(),
        )
    }
    .expect("pending_reopen check failed");
    assert_eq!(get_errno(), Errno::Pending, "pending_reopen check failed");

    let handle1 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle1.is_null(), "pending_reopen check failed");
    let add_ptr1 = unsafe { libc::dlsym(handle1, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr1.is_null(), "pending_reopen check failed");
    let add_fn1: AddFn = unsafe { core::mem::transmute(add_ptr1) };
    let hooked1 = unsafe { add_fn1(3, 4) };
    assert_eq!(hooked1, 2007, "pending_reopen check failed");

    unsafe { libc::dlclose(handle1) };
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );

    let handle2 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle2.is_null(), "pending_reopen check failed");
    let add_ptr2 = unsafe { libc::dlsym(handle2, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr2.is_null(), "pending_reopen check failed");
    let add_fn2: AddFn = unsafe { core::mem::transmute(add_ptr2) };
    let hooked2 = unsafe { add_fn2(5, 6) };
    assert_eq!(hooked2, 2011, "pending_reopen check failed");

    unsafe { libc::dlclose(handle2) };
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );
    let stale_unhook = unsafe { unhook(stub) };
    assert!(
        matches!(stale_unhook, Err(Errno::UnhookOnUnfinishedTask)),
        "pending_reopen check failed: {:?}",
        stale_unhook
    );

    let handle3 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle3.is_null(), "pending_reopen check failed");
    let add_ptr3 = unsafe { libc::dlsym(handle3, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr3.is_null(), "pending_reopen check failed");
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );
    let add_fn3: AddFn = unsafe { core::mem::transmute(add_ptr3) };
    let plain = unsafe { add_fn3(5, 6) };
    assert_eq!(plain, 11, "pending_reopen check failed");
    let missing = unsafe { unhook(stub) };
    assert!(
        matches!(missing, Err(Errno::UnhookNotFound)),
        "pending_reopen check failed: {:?}",
        missing
    );
    unsafe { libc::dlclose(handle3) };

    CALLBACK_HITS.store(0, Ordering::SeqCst);
    CALLBACK_ERR.store(-1, Ordering::SeqCst);
    CALLBACK_SYM.store(ptr::null_mut(), Ordering::SeqCst);
    let stub_cb = unsafe {
        hook_sym_name_callback(
            c"libctor_dtor_probe.so",
            c"ctor_dtor_probe_mul",
            replacement_add as *const c_void,
            orig_add_slot(),
            Some(reopen_hooked_cb),
            ptr::null_mut(),
        )
    }
    .expect("pending_reopen check failed");
    assert_eq!(get_errno(), Errno::Pending, "pending_reopen check failed");
    assert_eq!(
        CALLBACK_HITS.load(Ordering::SeqCst),
        0,
        "pending_reopen check failed"
    );

    let handle3 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle3.is_null(), "pending_reopen check failed");
    let mul_ptr1 = unsafe { libc::dlsym(handle3, c"ctor_dtor_probe_mul".as_ptr()) };
    assert!(!mul_ptr1.is_null(), "pending_reopen check failed");
    let mul_fn1: AddFn = unsafe { core::mem::transmute(mul_ptr1) };
    let hooked_mul1 = unsafe { mul_fn1(2, 3) };
    assert_eq!(hooked_mul1, 2006, "pending_reopen check failed");
    assert_eq!(
        CALLBACK_HITS.load(Ordering::SeqCst),
        1,
        "pending_reopen check failed"
    );
    assert_eq!(
        CALLBACK_ERR.load(Ordering::SeqCst),
        0,
        "pending_reopen check failed"
    );
    assert!(
        !CALLBACK_SYM.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );

    unsafe { libc::dlclose(handle3) };
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );
    CALLBACK_ERR.store(-1, Ordering::SeqCst);
    CALLBACK_SYM.store(ptr::null_mut(), Ordering::SeqCst);

    let handle4 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle4.is_null(), "pending_reopen check failed");
    let mul_ptr2 = unsafe { libc::dlsym(handle4, c"ctor_dtor_probe_mul".as_ptr()) };
    assert!(!mul_ptr2.is_null(), "pending_reopen check failed");
    let mul_fn2: AddFn = unsafe { core::mem::transmute(mul_ptr2) };
    let hooked_mul2 = unsafe { mul_fn2(4, 5) };
    assert_eq!(hooked_mul2, 2020, "pending_reopen check failed");
    assert_eq!(
        CALLBACK_HITS.load(Ordering::SeqCst),
        2,
        "pending_reopen check failed"
    );
    assert_eq!(
        CALLBACK_ERR.load(Ordering::SeqCst),
        0,
        "pending_reopen check failed"
    );
    assert!(
        !CALLBACK_SYM.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );

    unsafe { libc::dlclose(handle4) };
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );
    let stale_unhook_cb = unsafe { unhook(stub_cb) };
    assert!(
        matches!(stale_unhook_cb, Err(Errno::UnhookOnUnfinishedTask)),
        "pending_reopen check failed: {:?}",
        stale_unhook_cb
    );
    CALLBACK_ERR.store(-1, Ordering::SeqCst);
    CALLBACK_SYM.store(ptr::null_mut(), Ordering::SeqCst);

    let handle5 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle5.is_null(), "pending_reopen check failed");
    let mul_ptr3 = unsafe { libc::dlsym(handle5, c"ctor_dtor_probe_mul".as_ptr()) };
    assert!(!mul_ptr3.is_null(), "pending_reopen check failed");
    let mul_fn3: AddFn = unsafe { core::mem::transmute(mul_ptr3) };
    let plain_mul = unsafe { mul_fn3(4, 5) };
    assert_eq!(plain_mul, 20, "pending_reopen check failed");
    assert_eq!(
        CALLBACK_HITS.load(Ordering::SeqCst),
        2,
        "pending_reopen check failed"
    );
    assert_eq!(
        CALLBACK_ERR.load(Ordering::SeqCst),
        -1,
        "pending_reopen check failed"
    );
    assert!(
        CALLBACK_SYM.load(Ordering::SeqCst).is_null(),
        "pending_reopen check failed"
    );
    let missing_cb = unsafe { unhook(stub_cb) };
    assert!(
        matches!(missing_cb, Err(Errno::UnhookNotFound)),
        "pending_reopen check failed: {:?}",
        missing_cb
    );
    unsafe { libc::dlclose(handle5) };

    println!("pending_reopen_basic: PASS");
}
