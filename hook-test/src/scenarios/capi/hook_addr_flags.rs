use super::*;

pub(super) fn run() {
    // hook_func_addr_2 / sym_addr_2 flags 校验（固定 4 参签名）
    // SHARED_MODE + 无效 target：走 shared 安装主路径，rewriter 读 0x1 prologue 崩 → HookRewriteCrash(25)
    let f2_shared = unsafe {
        srx_inline_hook_hook_func_addr_2(
            0x1 as *mut c_void,
            0x2 as *mut c_void,
            core::ptr::null_mut(),
            1,
        )
    };
    assert!(f2_shared.is_null());
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 25);
    // MULTI + orig_addr=NULL：前置参数校验先拦截，应返回 InvalidArg(3)
    let s2_multi = unsafe {
        srx_inline_hook_hook_sym_addr_2(
            0x1 as *mut c_void,
            0x2 as *mut c_void,
            core::ptr::null_mut(),
            4,
        )
    };
    assert!(s2_multi.is_null());
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 3);
    // 非法高位 → InvalidArg(3)
    // SAFETY: 同上
    let f2_bad = unsafe {
        srx_inline_hook_hook_func_addr_2(
            0x1 as *mut c_void,
            0x2 as *mut c_void,
            core::ptr::null_mut(),
            0x100,
        )
    };
    assert!(f2_bad.is_null());
    assert_eq!(unsafe { srx_inline_hook_get_errno() }, 3);

    let target_fn: extern "C" fn(i64, i64) -> i64 =
        unsafe { core::mem::transmute(capi_intercept_target as *const c_void) };

    let f2_shared_ok = unsafe {
        srx_inline_hook_hook_func_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_addr_replacement as *mut c_void,
            core::ptr::null_mut(),
            1,
        )
    };
    assert!(!f2_shared_ok.is_null(), "hook_addr_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_addr_flags check failed"
    );
    assert_eq!(target_fn(1, 2), 703, "hook_addr_flags check failed");
    let f2_unique_conflict = unsafe {
        srx_inline_hook_hook_func_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_sym_replacement as *mut c_void,
            core::ptr::null_mut(),
            2,
        )
    };
    assert!(f2_unique_conflict.is_null(), "hook_addr_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        43,
        "hook_addr_flags check failed"
    );
    let f2_shared_unhook = unsafe { srx_inline_hook_unhook(f2_shared_ok) };
    assert_eq!(f2_shared_unhook, 0, "hook_addr_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_addr_flags check failed"
    );
    assert_eq!(target_fn(1, 2), 3, "hook_addr_flags check failed");

    let mut s2_multi_orig = core::ptr::null_mut();
    let s2_multi_ok = unsafe {
        srx_inline_hook_hook_sym_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_sym_replacement as *mut c_void,
            &mut s2_multi_orig,
            4,
        )
    };
    assert!(!s2_multi_ok.is_null(), "hook_addr_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_addr_flags check failed"
    );
    assert!(!s2_multi_orig.is_null(), "hook_addr_flags check failed");
    assert_eq!(target_fn(2, 3), 905, "hook_addr_flags check failed");
    let mut s2_multi_dup_orig = core::ptr::null_mut();
    let s2_multi_dup = unsafe {
        srx_inline_hook_hook_sym_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_sym_replacement as *mut c_void,
            &mut s2_multi_dup_orig,
            4,
        )
    };
    assert!(s2_multi_dup.is_null(), "hook_addr_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        44,
        "hook_addr_flags check failed"
    );
    let s2_shared_conflict = unsafe {
        srx_inline_hook_hook_sym_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_addr_replacement as *mut c_void,
            core::ptr::null_mut(),
            1,
        )
    };
    assert!(s2_shared_conflict.is_null(), "hook_addr_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        43,
        "hook_addr_flags check failed"
    );
    let s2_multi_unhook = unsafe { srx_inline_hook_unhook(s2_multi_ok) };
    assert_eq!(s2_multi_unhook, 0, "hook_addr_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_addr_flags check failed"
    );
    assert_eq!(target_fn(2, 3), 5, "hook_addr_flags check failed");

    let f2_bad_record_name = unsafe {
        srx_inline_hook_hook_func_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_addr_replacement as *mut c_void,
            core::ptr::null_mut(),
            8,
            c"bad lib.so".as_ptr(),
            c"named_target_hook".as_ptr(),
        )
    };
    assert!(f2_bad_record_name.is_null());
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "hook_addr_flags check failed"
    );
    let s2_bad_record_name = unsafe {
        srx_inline_hook_hook_sym_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_sym_replacement as *mut c_void,
            core::ptr::null_mut(),
            8,
            c"named-sym-lib.so".as_ptr(),
            c"bad sym".as_ptr(),
        )
    };
    assert!(s2_bad_record_name.is_null());
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "hook_addr_flags check failed"
    );

    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    let rec_reset = unsafe { srx_inline_hook_get_records(0x7FF) };
    if !rec_reset.is_null() {
        unsafe { libc::free(rec_reset as *mut c_void) };
    }
    let hook_func_addr_named = unsafe {
        srx_inline_hook_hook_func_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_addr_replacement as *mut c_void,
            core::ptr::null_mut(),
            8,
            c"named-hook-lib.so".as_ptr(),
            c"named_target_hook".as_ptr(),
        )
    };
    assert!(
        !hook_func_addr_named.is_null(),
        "hook_addr_flags check failed"
    );
    let target_fn: extern "C" fn(i64, i64) -> i64 =
        unsafe { core::mem::transmute(capi_intercept_target as *const c_void) };
    assert_eq!(target_fn(7, 8), 715, "hook_addr_flags check failed");
    let rec_named_ptr = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(!rec_named_ptr.is_null(), "hook_addr_flags check failed");
    let rec_named = unsafe { core::ffi::CStr::from_ptr(rec_named_ptr) }
        .to_str()
        .expect("hook records named utf8");
    assert!(
        rec_named.contains("named-hook-lib.so"),
        "hook_addr_flags check failed: {}",
        rec_named
    );
    assert!(
        rec_named.contains("named_target_hook"),
        "hook_addr_flags check failed: {}",
        rec_named
    );
    assert!(
        rec_named.lines().any(|line| {
            let cols: Vec<_> = line.split(',').collect();
            cols.len() >= 11 && cols[9].chars().all(|c| c.is_ascii_hexdigit())
        }),
        "hook_addr_flags check failed: {}",
        rec_named
    );
    assert!(
        rec_named
            .lines()
            .any(|line| line.split(',').nth(10) == Some("8")),
        "hook_addr_flags check failed: {}",
        rec_named
    );
    unsafe {
        libc::free(rec_named_ptr as *mut c_void);
        srx_inline_hook_set_recordable(false);
    }
    let hook_func_addr_named_unhook = unsafe { srx_inline_hook_unhook(hook_func_addr_named) };
    assert_eq!(
        hook_func_addr_named_unhook, 0,
        "hook_addr_flags check failed"
    );
    assert_eq!(target_fn(7, 8), 15, "hook_addr_flags check failed");

    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    let rec_reset = unsafe { srx_inline_hook_get_records(0x7FF) };
    if !rec_reset.is_null() {
        unsafe { libc::free(rec_reset as *mut c_void) };
    }
    let hook_sym_addr_named = unsafe {
        srx_inline_hook_hook_sym_addr_2(
            capi_intercept_target as *mut c_void,
            capi_hook_sym_replacement as *mut c_void,
            core::ptr::null_mut(),
            8,
            c"named-sym-lib.so".as_ptr(),
            c"named_sym_addr_hook".as_ptr(),
        )
    };
    assert!(
        !hook_sym_addr_named.is_null(),
        "hook_addr_flags check failed"
    );
    assert_eq!(target_fn(9, 10), 919, "hook_addr_flags check failed");
    let rec_sym_ptr = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(!rec_sym_ptr.is_null(), "hook_addr_flags check failed");
    let rec_sym = unsafe { core::ffi::CStr::from_ptr(rec_sym_ptr) }
        .to_str()
        .expect("hook_sym_addr_2 records utf8");
    assert!(
        rec_sym.contains("named-sym-lib.so"),
        "hook_addr_flags check failed: {}",
        rec_sym
    );
    assert!(
        rec_sym.contains("named_sym_addr_hook"),
        "hook_addr_flags check failed: {}",
        rec_sym
    );
    assert!(
        rec_sym.contains("hook_sym_addr"),
        "hook_addr_flags check failed: {}",
        rec_sym
    );
    unsafe {
        libc::free(rec_sym_ptr as *mut c_void);
        srx_inline_hook_set_recordable(false);
    }
    let hook_sym_addr_named_unhook = unsafe { srx_inline_hook_unhook(hook_sym_addr_named) };
    assert_eq!(
        hook_sym_addr_named_unhook, 0,
        "hook_addr_flags check failed"
    );
    assert_eq!(target_fn(9, 10), 19, "hook_addr_flags check failed");

    println!("capi_hook_addr_flags: PASS");
}
