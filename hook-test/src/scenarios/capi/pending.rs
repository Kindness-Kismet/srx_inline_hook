use super::*;

pub(super) fn run() {
    CAPI_PENDING_ORIG.store(ptr::null_mut(), Ordering::SeqCst);
    let pending_add_slot = CAPI_PENDING_ORIG.as_ptr() as *mut *mut c_void;
    let pending_stub = unsafe {
        srx_inline_hook_hook_sym_name(
            c"libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_add".as_ptr(),
            capi_pending_replacement as *mut c_void,
            pending_add_slot,
        )
    };
    assert!(!pending_stub.is_null(), "pending check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        1,
        "pending check failed"
    );
    assert!(
        CAPI_PENDING_ORIG.load(Ordering::SeqCst).is_null(),
        "pending check failed"
    );
    let pending_handle =
        unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!pending_handle.is_null(), "pending check failed");
    let add_ptr = unsafe { libc::dlsym(pending_handle, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr.is_null(), "pending check failed");
    assert!(
        !CAPI_PENDING_ORIG.load(Ordering::SeqCst).is_null(),
        "pending check failed"
    );
    let add_fn: ProbeFn = unsafe { mem::transmute(add_ptr) };
    assert_eq!(unsafe { add_fn(3, 4) }, 1007, "pending check failed");
    let pending_unhook = unsafe { srx_inline_hook_unhook(pending_stub) };
    assert_eq!(pending_unhook, 0, "pending check failed");
    assert!(
        CAPI_PENDING_ORIG.load(Ordering::SeqCst).is_null(),
        "pending check failed"
    );
    assert_eq!(unsafe { add_fn(3, 4) }, 7, "pending check failed");
    unsafe { libc::dlclose(pending_handle) };

    CAPI_PENDING_ORIG.store(ptr::null_mut(), Ordering::SeqCst);
    CAPI_PENDING_CB_HITS.store(0, Ordering::SeqCst);
    CAPI_PENDING_CB_ERR.store(-1, Ordering::SeqCst);
    CAPI_PENDING_CB_SYM.store(ptr::null_mut(), Ordering::SeqCst);
    CAPI_PENDING_CB_NEW_ADDR.store(ptr::null_mut(), Ordering::SeqCst);
    CAPI_PENDING_CB_ARG.store(ptr::null_mut(), Ordering::Release);
    CAPI_PENDING_CB_ORIG_ADDR.store(ptr::null_mut(), Ordering::Release);
    *CAPI_PENDING_CB_LIB_NAME_TEXT
        .lock()
        .expect("reset pending cb lib") = None;
    *CAPI_PENDING_CB_SYM_NAME_TEXT
        .lock()
        .expect("reset pending cb sym") = None;
    let mut pending_cb_marker = 0x3344_i32;
    let pending_cb_arg = &mut pending_cb_marker as *mut c_int as *mut c_void;
    let pending_cb_stub = unsafe {
        srx_inline_hook_hook_sym_name_callback(
            c"./libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_mul".as_ptr(),
            capi_pending_replacement as *mut c_void,
            pending_add_slot,
            Some(capi_pending_hooked_cb),
            pending_cb_arg,
        )
    };
    assert!(!pending_cb_stub.is_null(), "pending check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        1,
        "pending check failed"
    );
    assert_eq!(
        CAPI_PENDING_CB_HITS.load(Ordering::SeqCst),
        0,
        "pending check failed"
    );
    let pending_handle2 =
        unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!pending_handle2.is_null(), "pending check failed");
    let mul_ptr = unsafe { libc::dlsym(pending_handle2, c"ctor_dtor_probe_mul".as_ptr()) };
    assert!(!mul_ptr.is_null(), "pending check failed");
    assert_eq!(
        CAPI_PENDING_CB_HITS.load(Ordering::SeqCst),
        1,
        "pending check failed"
    );
    assert_eq!(
        CAPI_PENDING_CB_ERR.load(Ordering::SeqCst),
        0,
        "pending check failed"
    );
    let pending_seen_lib = CAPI_PENDING_CB_LIB_NAME_TEXT
        .lock()
        .expect("read pending cb lib")
        .clone()
        .expect("pending cb lib set");
    let pending_seen_sym = CAPI_PENDING_CB_SYM_NAME_TEXT
        .lock()
        .expect("read pending cb sym")
        .clone()
        .expect("pending cb sym set");
    assert_eq!(
        pending_seen_lib, "./libctor_dtor_probe.so",
        "pending check failed"
    );
    assert_eq!(
        pending_seen_sym, "ctor_dtor_probe_mul",
        "pending check failed"
    );
    assert_eq!(
        CAPI_PENDING_CB_ARG.load(Ordering::Acquire),
        pending_cb_arg,
        "pending check failed"
    );
    assert_eq!(
        CAPI_PENDING_CB_NEW_ADDR.load(Ordering::Acquire),
        capi_pending_replacement as *mut c_void,
        "pending check failed"
    );
    assert!(
        !CAPI_PENDING_CB_SYM.load(Ordering::Acquire).is_null(),
        "pending check failed"
    );
    assert_eq!(
        CAPI_PENDING_CB_ORIG_ADDR.load(Ordering::Acquire),
        pending_add_slot as *mut c_void,
        "pending check failed"
    );
    assert!(
        !CAPI_PENDING_CB_SYM.load(Ordering::SeqCst).is_null(),
        "pending check failed"
    );
    let mul_fn: ProbeFn = unsafe { mem::transmute(mul_ptr) };
    assert_eq!(unsafe { mul_fn(3, 4) }, 1012, "pending check failed");
    let pending_cb_unhook = unsafe { srx_inline_hook_unhook(pending_cb_stub) };
    assert_eq!(pending_cb_unhook, 0, "pending check failed");
    assert_eq!(unsafe { mul_fn(3, 4) }, 12, "pending check failed");
    unsafe { libc::dlclose(pending_handle2) };
    println!("capi_pending: PASS");
}
