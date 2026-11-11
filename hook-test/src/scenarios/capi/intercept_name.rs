use core::ffi::CStr;

use super::*;

pub(super) fn run() {
    let pending_intercept_stub = unsafe {
        srx_inline_hook_intercept_sym_name(
            c"libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_add".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0,
        )
    };
    assert!(
        !pending_intercept_stub.is_null(),
        "intercept_name check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        1,
        "intercept_name check failed"
    );
    let pending_intercept_handle =
        unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(
        !pending_intercept_handle.is_null(),
        "intercept_name check failed"
    );
    let pending_add_ptr =
        unsafe { libc::dlsym(pending_intercept_handle, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!pending_add_ptr.is_null(), "intercept_name check failed");
    let pending_add_fn: ProbeFn = unsafe { mem::transmute(pending_add_ptr) };
    assert_eq!(
        unsafe { pending_add_fn(3, 4) },
        7,
        "intercept_name check failed"
    );
    let pending_intercept_unhook = unsafe { srx_inline_hook_unintercept(pending_intercept_stub) };
    assert_eq!(pending_intercept_unhook, 0, "intercept_name check failed");
    unsafe { libc::dlclose(pending_intercept_handle) };

    CAPI_INTERCEPT_CB_HITS.store(0, Ordering::SeqCst);
    CAPI_INTERCEPT_CB_ARG.store(ptr::null_mut(), Ordering::Release);
    *CAPI_INTERCEPT_CB_LIB_NAME_TEXT
        .lock()
        .expect("reset pending intercept cb lib") = None;
    *CAPI_INTERCEPT_CB_SYM_NAME_TEXT
        .lock()
        .expect("reset pending intercept cb sym") = None;
    let mut pending_intercept_cb_marker = 0x7788_i32;
    let pending_intercept_cb_arg = &mut pending_intercept_cb_marker as *mut c_int as *mut c_void;
    let pending_intercept_cb_stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"./libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_add".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0,
            capi_intercepted_cb as *mut c_void,
            pending_intercept_cb_arg,
        )
    };
    assert!(
        !pending_intercept_cb_stub.is_null(),
        "intercept_name check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        1,
        "intercept_name check failed"
    );
    assert_eq!(
        CAPI_INTERCEPT_CB_HITS.load(Ordering::SeqCst),
        0,
        "intercept_name check failed"
    );
    let pending_intercept_handle2 =
        unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(
        !pending_intercept_handle2.is_null(),
        "intercept_name check failed"
    );
    let pending_add_ptr2 =
        unsafe { libc::dlsym(pending_intercept_handle2, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!pending_add_ptr2.is_null(), "intercept_name check failed");
    let pending_add_fn2: ProbeFn = unsafe { mem::transmute(pending_add_ptr2) };
    assert_eq!(
        unsafe { pending_add_fn2(8, 9) },
        17,
        "intercept_name check failed"
    );
    assert_eq!(
        CAPI_INTERCEPT_CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_name check failed"
    );
    let pending_intercept_seen_lib = CAPI_INTERCEPT_CB_LIB_NAME_TEXT
        .lock()
        .expect("read pending intercept cb lib")
        .clone()
        .expect("pending intercept cb lib set");
    let pending_intercept_seen_sym = CAPI_INTERCEPT_CB_SYM_NAME_TEXT
        .lock()
        .expect("read pending intercept cb sym")
        .clone()
        .expect("pending intercept cb sym set");
    assert_eq!(
        pending_intercept_seen_lib, "./libctor_dtor_probe.so",
        "intercept_name check failed"
    );
    assert_eq!(
        pending_intercept_seen_sym, "ctor_dtor_probe_add",
        "intercept_name check failed"
    );
    assert_eq!(
        CAPI_INTERCEPT_CB_ARG.load(Ordering::Acquire),
        pending_intercept_cb_arg,
        "intercept_name check failed"
    );
    let pending_intercept_cb_unhook =
        unsafe { srx_inline_hook_unintercept(pending_intercept_cb_stub) };
    assert_eq!(
        pending_intercept_cb_unhook, 0,
        "intercept_name check failed"
    );
    unsafe { libc::dlclose(pending_intercept_handle2) };

    CAPI_INTERCEPT_CB_HITS.store(0, Ordering::SeqCst);
    let bad_intercept_cb = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0x100,
            capi_intercepted_cb as *mut c_void,
            ptr::null_mut(),
        )
    };
    assert!(bad_intercept_cb.is_null(), "intercept_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_name check failed"
    );
    assert_eq!(
        CAPI_INTERCEPT_CB_HITS.load(Ordering::SeqCst),
        0,
        "intercept_name check failed"
    );

    let intercept_stub = unsafe {
        srx_inline_hook_intercept_sym_name(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0,
        )
    };
    assert!(!intercept_stub.is_null(), "intercept_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_name check failed"
    );
    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    let intercept_unhook = unsafe { srx_inline_hook_unintercept(intercept_stub) };
    assert_eq!(intercept_unhook, 0, "intercept_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_name check failed"
    );
    let intercept_unrec_ptr = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(
        !intercept_unrec_ptr.is_null(),
        "intercept_name check failed"
    );
    let intercept_unrec = unsafe { CStr::from_ptr(intercept_unrec_ptr) }
        .to_str()
        .expect("intercept records utf8");
    assert!(
        intercept_unrec.contains("unintercept"),
        "intercept_name check failed: {}",
        intercept_unrec
    );
    unsafe {
        libc::free(intercept_unrec_ptr as *mut c_void);
        srx_inline_hook_set_recordable(false);
    }

    let strlen_handle = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!strlen_handle.is_null(), "intercept_name check failed");
    let strlen_ptr = unsafe { libc::dlsym(strlen_handle, c"strlen".as_ptr()) };
    assert!(!strlen_ptr.is_null(), "intercept_name check failed");
    let mut strlen_info: libc::Dl_info = unsafe { mem::zeroed() };
    assert_ne!(
        unsafe { libc::dladdr(strlen_ptr, &mut strlen_info) },
        0,
        "intercept_name check failed"
    );
    assert!(
        !strlen_info.dli_fname.is_null(),
        "intercept_name check failed"
    );
    let libc_path = unsafe { CStr::from_ptr(strlen_info.dli_fname) };

    let intercept_path_stub = unsafe {
        srx_inline_hook_intercept_sym_name(
            libc_path.as_ptr(),
            c"strlen".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0,
        )
    };
    assert!(
        !intercept_path_stub.is_null(),
        "intercept_name check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_name check failed"
    );
    let intercept_path_unhook = unsafe { srx_inline_hook_unintercept(intercept_path_stub) };
    assert_eq!(intercept_path_unhook, 0, "intercept_name check failed");

    CAPI_INTERCEPT_CB_HITS.store(0, Ordering::SeqCst);
    CAPI_INTERCEPT_CB_ARG.store(ptr::null_mut(), Ordering::Release);
    *CAPI_INTERCEPT_CB_LIB_NAME_TEXT
        .lock()
        .expect("reset intercept cb lib") = None;
    *CAPI_INTERCEPT_CB_SYM_NAME_TEXT
        .lock()
        .expect("reset intercept cb sym") = None;
    let mut intercept_cb_marker = 0x55aa_i32;
    let intercept_cb_arg = &mut intercept_cb_marker as *mut c_int as *mut c_void;
    let intercept_cb_stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            libc_path.as_ptr(),
            c"strlen".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0,
            capi_intercepted_cb as *mut c_void,
            intercept_cb_arg,
        )
    };
    assert!(!intercept_cb_stub.is_null(), "intercept_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_name check failed"
    );
    assert_eq!(
        CAPI_INTERCEPT_CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_name check failed"
    );
    let intercept_seen_lib = CAPI_INTERCEPT_CB_LIB_NAME_TEXT
        .lock()
        .expect("read intercept cb lib")
        .clone()
        .expect("intercept cb lib set");
    let intercept_seen_sym = CAPI_INTERCEPT_CB_SYM_NAME_TEXT
        .lock()
        .expect("read intercept cb sym")
        .clone()
        .expect("intercept cb sym set");
    let expected_lib = libc_path.to_str().expect("libc path utf8");
    assert_eq!(
        intercept_seen_lib, expected_lib,
        "intercept_name check failed"
    );
    assert_eq!(intercept_seen_sym, "strlen", "intercept_name check failed");
    assert_eq!(
        CAPI_INTERCEPT_CB_ARG.load(Ordering::Acquire),
        intercept_cb_arg,
        "intercept_name check failed"
    );
    CAPI_INTERCEPT_CB_HITS.store(0, Ordering::SeqCst);
    let intercept_cb_dup = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            libc_path.as_ptr(),
            c"strlen".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0,
            capi_intercepted_cb as *mut c_void,
            intercept_cb_arg,
        )
    };
    assert!(intercept_cb_dup.is_null(), "intercept_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        10,
        "intercept_name check failed"
    );
    assert_eq!(
        CAPI_INTERCEPT_CB_HITS.load(Ordering::SeqCst),
        1,
        "intercept_name check failed"
    );
    let intercept_cb_unhook = unsafe { srx_inline_hook_unintercept(intercept_cb_stub) };
    assert_eq!(intercept_cb_unhook, 0, "intercept_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_name check failed"
    );

    CAPI_INTERCEPT_CB_HITS.store(0, Ordering::SeqCst);
    let intercept_cb_null = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            capi_intercept_pre as *mut c_void,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert!(!intercept_cb_null.is_null(), "intercept_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_name check failed"
    );
    assert_eq!(
        CAPI_INTERCEPT_CB_HITS.load(Ordering::SeqCst),
        0,
        "intercept_name check failed"
    );
    let intercept_cb_null_unhook = unsafe { srx_inline_hook_unintercept(intercept_cb_null) };
    assert_eq!(intercept_cb_null_unhook, 0, "intercept_name check failed");

    // unintercept(NULL)：返 -1 + InvalidArg(3)
    // SAFETY: NULL 走 InvalidArg 分支
    let ui_null = unsafe { srx_inline_hook_unintercept(ptr::null_mut()) };
    assert_eq!(ui_null, -1);
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 3);
    // unintercept(非 NULL)：当前最小实现下，未知 stub 返 -1 + UnhookNotFound(27)
    let ui_any = unsafe { srx_inline_hook_unintercept(0x1 as *mut c_void) };
    assert_eq!(ui_any, -1);
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 27);
    unsafe { libc::dlclose(strlen_handle) };
    println!("capi_intercept_name: PASS");
}
