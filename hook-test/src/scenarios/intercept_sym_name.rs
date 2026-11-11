// intercept_sym_name 最小链：按 so + 符号名注册 pre 回调，调用目标时应命中
// 先覆盖已加载 so 成功路径与 unintercept 收尾

use core::ffi::{c_char, c_int, c_void};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use srx_inline_hook::{active_hook_count, diagnose, list_hooks, trampoline_stats};

unsafe extern "C" {
    fn srx_inline_hook_intercept_sym_name(
        lib_name: *const c_char,
        sym_name: *const c_char,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
    ) -> *mut c_void;
    fn srx_inline_hook_intercept_sym_name_callback(
        lib_name: *const c_char,
        sym_name: *const c_char,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        intercepted: *mut c_void,
        intercepted_arg: *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_unintercept(stub: *mut c_void) -> c_int;
    fn srx_inline_hook_get_errno() -> c_int;
}

type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;

static PRE_HITS: AtomicUsize = AtomicUsize::new(0);
static CB_HITS: AtomicUsize = AtomicUsize::new(0);
static CB_ERROR: AtomicUsize = AtomicUsize::new(usize::MAX);
static CB_SYM_ADDR: AtomicUsize = AtomicUsize::new(0);
static CB_PRE: AtomicUsize = AtomicUsize::new(0);
static CB_DATA: AtomicUsize = AtomicUsize::new(0);
static CB_ARG: AtomicUsize = AtomicUsize::new(0);

extern "C" fn pre_cb(_ctx: *mut c_void, _data: *mut c_void) {
    PRE_HITS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn intercepted_cb(
    error: c_int,
    _lib_name: *const c_char,
    _sym_name: *const c_char,
    sym_addr: *const c_void,
    pre: *mut c_void,
    data: *mut c_void,
    arg: *mut c_void,
) {
    CB_HITS.fetch_add(1, Ordering::SeqCst);
    CB_ERROR.store(error as usize, Ordering::SeqCst);
    CB_SYM_ADDR.store(sym_addr as usize, Ordering::SeqCst);
    CB_PRE.store(pre as usize, Ordering::SeqCst);
    CB_DATA.store(data as usize, Ordering::SeqCst);
    CB_ARG.store(arg as usize, Ordering::SeqCst);
}

pub fn intercept_sym_name_basic() {
    PRE_HITS.store(0, Ordering::SeqCst);

    let handle = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        println!("intercept_sym_name_basic: skipped");
        return;
    }
    let strlen_ptr = unsafe { libc::dlsym(handle, c"strlen".as_ptr()) };
    if strlen_ptr.is_null() {
        println!("intercept_sym_name_basic: skipped");
        return;
    }
    let strlen_fn: StrlenFn = unsafe { mem::transmute(strlen_ptr) };

    let stub = unsafe {
        srx_inline_hook_intercept_sym_name(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            pre_cb as *mut c_void,
            ptr::null_mut(),
            0,
        )
    };
    assert!(!stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_sym_name check failed"
    );

    let probe = c"intercept-sym-name";
    let len = unsafe { strlen_fn(probe.as_ptr()) };
    assert_eq!(len, 18, "intercept_sym_name check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );

    let rc = unsafe { srx_inline_hook_unintercept(stub) };
    assert_eq!(rc, 0, "intercept_sym_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_sym_name check failed"
    );

    let len2 = unsafe { strlen_fn(c"abc".as_ptr()) };
    assert_eq!(len2, 3, "intercept_sym_name check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );

    println!("intercept_sym_name_basic: PASS");
}

pub fn intercept_sym_name_callback_basic() {
    CB_HITS.store(0, Ordering::SeqCst);
    CB_ERROR.store(usize::MAX, Ordering::SeqCst);
    CB_SYM_ADDR.store(0, Ordering::SeqCst);
    CB_PRE.store(0, Ordering::SeqCst);
    CB_DATA.store(0, Ordering::SeqCst);
    CB_ARG.store(0, Ordering::SeqCst);

    let mut marker = 123usize;
    let callback_data = 0x1357usize as *mut c_void;
    let expected_pre = pre_cb as *mut c_void as usize;
    let bad_flags_stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            pre_cb as *mut c_void,
            callback_data,
            0x100,
            intercepted_cb as *mut c_void,
            &mut marker as *mut usize as *mut c_void,
        )
    };
    assert!(bad_flags_stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );

    CB_ERROR.store(usize::MAX, Ordering::SeqCst);
    CB_SYM_ADDR.store(0, Ordering::SeqCst);
    CB_ARG.store(0, Ordering::SeqCst);
    let fail_stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libc.so".as_ptr(),
            c"srx_absent_symbol_xyz".as_ptr(),
            pre_cb as *mut c_void,
            callback_data,
            0,
            intercepted_cb as *mut c_void,
            &mut marker as *mut usize as *mut c_void,
        )
    };
    assert!(fail_stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_ne!(
        CB_ERROR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_SYM_ADDR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_PRE.load(Ordering::SeqCst),
        expected_pre,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_DATA.load(Ordering::SeqCst),
        callback_data as usize,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ARG.load(Ordering::SeqCst),
        (&mut marker as *mut usize) as usize,
        "intercept_sym_name check failed"
    );

    CB_HITS.store(0, Ordering::SeqCst);
    CB_ERROR.store(usize::MAX, Ordering::SeqCst);
    CB_SYM_ADDR.store(0, Ordering::SeqCst);
    CB_PRE.store(0, Ordering::SeqCst);
    CB_DATA.store(0, Ordering::SeqCst);
    CB_ARG.store(0, Ordering::SeqCst);

    let handle = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        println!("intercept_sym_name_callback_basic: skipped");
        return;
    }
    let strlen_ptr = unsafe { libc::dlsym(handle, c"strlen".as_ptr()) };
    if strlen_ptr.is_null() {
        println!("intercept_sym_name_callback_basic: skipped");
        return;
    }

    let ok_stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            pre_cb as *mut c_void,
            callback_data,
            0,
            intercepted_cb as *mut c_void,
            &mut marker as *mut usize as *mut c_void,
        )
    };
    assert!(!ok_stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ERROR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_PRE.load(Ordering::SeqCst),
        expected_pre,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_DATA.load(Ordering::SeqCst),
        callback_data as usize,
        "intercept_sym_name check failed"
    );

    CB_HITS.store(0, Ordering::SeqCst);
    CB_ERROR.store(usize::MAX, Ordering::SeqCst);
    CB_SYM_ADDR.store(0, Ordering::SeqCst);
    CB_PRE.store(0, Ordering::SeqCst);
    CB_DATA.store(0, Ordering::SeqCst);
    CB_ARG.store(0, Ordering::SeqCst);
    let dup_stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            pre_cb as *mut c_void,
            callback_data,
            0,
            intercepted_cb as *mut c_void,
            &mut marker as *mut usize as *mut c_void,
        )
    };
    assert!(dup_stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        10,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ERROR.load(Ordering::SeqCst),
        10,
        "intercept_sym_name check failed"
    );
    assert_ne!(
        CB_SYM_ADDR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_PRE.load(Ordering::SeqCst),
        expected_pre,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_DATA.load(Ordering::SeqCst),
        callback_data as usize,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ARG.load(Ordering::SeqCst),
        (&mut marker as *mut usize) as usize,
        "intercept_sym_name check failed"
    );

    let rc = unsafe { srx_inline_hook_unintercept(ok_stub) };
    assert_eq!(rc, 0, "intercept_sym_name check failed");
    println!("intercept_sym_name_callback_basic: PASS");
}

pub fn intercept_sym_name_pending_basic() {
    PRE_HITS.store(0, Ordering::SeqCst);

    let stub = unsafe {
        srx_inline_hook_intercept_sym_name(
            c"libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_add".as_ptr(),
            pre_cb as *mut c_void,
            ptr::null_mut(),
            0,
        )
    };
    assert!(!stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        1,
        "intercept_sym_name check failed"
    );

    let handle = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "intercept_sym_name check failed");

    type AddFn = unsafe extern "C" fn(c_int, c_int) -> c_int;
    let add_ptr = unsafe { libc::dlsym(handle, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr.is_null(), "intercept_sym_name check failed");
    let add_fn: AddFn = unsafe { mem::transmute(add_ptr) };
    let v = unsafe { add_fn(3, 4) };
    assert_eq!(v, 7, "intercept_sym_name check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );

    let rc = unsafe { srx_inline_hook_unintercept(stub) };
    assert_eq!(rc, 0, "intercept_sym_name check failed");
    unsafe { libc::dlclose(handle) };
    println!("intercept_sym_name_pending_basic: PASS");
}

pub fn intercept_sym_name_pending_callback_basic() {
    PRE_HITS.store(0, Ordering::SeqCst);
    CB_HITS.store(0, Ordering::SeqCst);
    CB_ERROR.store(usize::MAX, Ordering::SeqCst);
    CB_SYM_ADDR.store(0, Ordering::SeqCst);
    CB_PRE.store(0, Ordering::SeqCst);
    CB_DATA.store(0, Ordering::SeqCst);
    CB_ARG.store(0, Ordering::SeqCst);

    let mut marker = 456usize;
    let callback_data = 0x2468usize as *mut c_void;
    let expected_pre = pre_cb as *mut c_void as usize;
    let stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_add".as_ptr(),
            pre_cb as *mut c_void,
            callback_data,
            0,
            intercepted_cb as *mut c_void,
            &mut marker as *mut usize as *mut c_void,
        )
    };
    assert!(!stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );

    let handle = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "intercept_sym_name check failed");

    type AddFn = unsafe extern "C" fn(c_int, c_int) -> c_int;
    let add_ptr = unsafe { libc::dlsym(handle, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr.is_null(), "intercept_sym_name check failed");
    let add_fn: AddFn = unsafe { mem::transmute(add_ptr) };
    let v = unsafe { add_fn(8, 9) };
    assert_eq!(v, 17, "intercept_sym_name check failed");
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ERROR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_ne!(
        CB_SYM_ADDR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_PRE.load(Ordering::SeqCst),
        expected_pre,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_DATA.load(Ordering::SeqCst),
        callback_data as usize,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ARG.load(Ordering::SeqCst),
        (&mut marker as *mut usize) as usize,
        "intercept_sym_name check failed"
    );

    let rc = unsafe { srx_inline_hook_unintercept(stub) };
    assert_eq!(rc, 0, "intercept_sym_name check failed");
    unsafe { libc::dlclose(handle) };
    println!("intercept_sym_name_pending_callback_basic: PASS");
}

pub fn intercept_sym_name_pending_reopen_basic() {
    let before_stats = trampoline_stats();
    let before_hooks = active_hook_count();
    let before_list_len = list_hooks().len();
    let before_diag = diagnose();

    PRE_HITS.store(0, Ordering::SeqCst);
    CB_HITS.store(0, Ordering::SeqCst);
    CB_ERROR.store(usize::MAX, Ordering::SeqCst);
    CB_SYM_ADDR.store(0, Ordering::SeqCst);
    CB_PRE.store(0, Ordering::SeqCst);
    CB_DATA.store(0, Ordering::SeqCst);
    CB_ARG.store(0, Ordering::SeqCst);

    let mut marker = 789usize;
    let callback_data = 0x369cusize as *mut c_void;
    let expected_pre = pre_cb as *mut c_void as usize;
    let stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_add".as_ptr(),
            pre_cb as *mut c_void,
            callback_data,
            0,
            intercepted_cb as *mut c_void,
            &mut marker as *mut usize as *mut c_void,
        )
    };
    assert!(!stub.is_null(), "intercept_sym_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );

    let handle1 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle1.is_null(), "intercept_sym_name check failed");
    let add_ptr1 = unsafe { libc::dlsym(handle1, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr1.is_null(), "intercept_sym_name check failed");
    let add_fn1: unsafe extern "C" fn(c_int, c_int) -> c_int = unsafe { mem::transmute(add_ptr1) };
    assert_eq!(
        unsafe { add_fn1(3, 4) },
        7,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ERROR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_ne!(
        CB_SYM_ADDR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_PRE.load(Ordering::SeqCst),
        expected_pre,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_DATA.load(Ordering::SeqCst),
        callback_data as usize,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ARG.load(Ordering::SeqCst),
        (&mut marker as *mut usize) as usize,
        "intercept_sym_name check failed"
    );

    unsafe { libc::dlclose(handle1) };
    PRE_HITS.store(0, Ordering::SeqCst);
    CB_ERROR.store(usize::MAX, Ordering::SeqCst);
    CB_SYM_ADDR.store(0, Ordering::SeqCst);
    CB_PRE.store(0, Ordering::SeqCst);
    CB_DATA.store(0, Ordering::SeqCst);
    CB_ARG.store(0, Ordering::SeqCst);

    let handle2 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle2.is_null(), "intercept_sym_name check failed");
    let add_ptr2 = unsafe { libc::dlsym(handle2, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr2.is_null(), "intercept_sym_name check failed");
    let add_fn2: unsafe extern "C" fn(c_int, c_int) -> c_int = unsafe { mem::transmute(add_ptr2) };
    assert_eq!(
        unsafe { add_fn2(8, 9) },
        17,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        PRE_HITS.load(Ordering::SeqCst),
        1,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_HITS.load(Ordering::SeqCst),
        2,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ERROR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_ne!(
        CB_SYM_ADDR.load(Ordering::SeqCst),
        0,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_PRE.load(Ordering::SeqCst),
        expected_pre,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_DATA.load(Ordering::SeqCst),
        callback_data as usize,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        CB_ARG.load(Ordering::SeqCst),
        (&mut marker as *mut usize) as usize,
        "intercept_sym_name check failed"
    );

    let rc = unsafe { srx_inline_hook_unintercept(stub) };
    assert_eq!(rc, 0, "intercept_sym_name check failed");
    unsafe { libc::dlclose(handle2) };

    let after_stats = trampoline_stats();
    let after_hooks = active_hook_count();
    let after_list_len = list_hooks().len();
    let after_diag = diagnose();
    assert_eq!(
        after_stats.slots_used, before_stats.slots_used,
        "intercept_sym_name check failed"
    );
    assert_eq!(after_hooks, before_hooks, "intercept_sym_name check failed");
    assert_eq!(
        after_list_len, before_list_len,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        after_diag.active_hooks, before_diag.active_hooks,
        "intercept_sym_name check failed"
    );
    assert_eq!(
        after_diag.trampoline.slots_used, before_diag.trampoline.slots_used,
        "intercept_sym_name check failed"
    );

    println!("intercept_sym_name_pending_reopen_basic: PASS");
}
