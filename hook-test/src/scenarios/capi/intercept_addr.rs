use super::*;

pub(super) fn run() {
    // intercept_sym_name 校验 NULL 前置序与未知句柄卸载语义
    // SAFETY: 故意 pre=NULL 触发 InvalidArg 路径
    let intercept_null_pre = unsafe {
        srx_inline_hook_intercept_sym_name(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(intercept_null_pre.is_null(), "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_addr check failed"
    );
    // 再测合法参数路径：已加载 libc.so 下应成功返回 stub
    extern "C" fn capi_intercept_pre(_ctx: *mut c_void, _data: *mut c_void) {}
    let intercept_instr_bad_record_lib = unsafe {
        srx_inline_hook_intercept_instr_addr(
            capi_intercept_target as *mut c_void,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            4,
            c"bad lib.so".as_ptr(),
            c"named_instr".as_ptr(),
        )
    };
    assert!(
        intercept_instr_bad_record_lib.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_addr check failed"
    );
    let intercept_instr_bad_record_sym = unsafe {
        srx_inline_hook_intercept_instr_addr(
            capi_intercept_target as *mut c_void,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            4,
            c"named-lib.so".as_ptr(),
            c"bad sym".as_ptr(),
        )
    };
    assert!(
        intercept_instr_bad_record_sym.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_addr check failed"
    );
    let intercept_instr_stub = unsafe {
        srx_inline_hook_intercept_instr_addr(
            capi_intercept_target as *mut c_void,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(
        !intercept_instr_stub.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    let intercept_instr_unhook = unsafe { srx_inline_hook_unintercept(intercept_instr_stub) };
    assert_eq!(intercept_instr_unhook, 0, "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );

    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    let rec_reset = unsafe { srx_inline_hook_get_records(0x7FF) };
    if !rec_reset.is_null() {
        unsafe { libc::free(rec_reset as *mut c_void) };
    }
    let intercept_instr_named = unsafe {
        srx_inline_hook_intercept_instr_addr(
            capi_intercept_target as *mut c_void,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            4,
            c"named-instr-lib.so".as_ptr(),
            c"named_intercept_instr".as_ptr(),
        )
    };
    assert!(
        !intercept_instr_named.is_null(),
        "intercept_addr check failed"
    );
    let rec_named_ptr = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(!rec_named_ptr.is_null(), "intercept_addr check failed");
    let rec_named = unsafe { core::ffi::CStr::from_ptr(rec_named_ptr) }
        .to_str()
        .expect("intercept_instr_addr records utf8");
    assert!(
        rec_named.contains("named-instr-lib.so"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.contains("named_intercept_instr"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.contains("intercept_instr_addr"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.lines().any(|line| {
            let cols: Vec<_> = line.split(',').collect();
            cols.len() >= 11 && cols[9].chars().all(|c| c.is_ascii_hexdigit())
        }),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.lines().any(|line| {
            let cols: Vec<_> = line.split(',').collect();
            cols.len() >= 11 && cols[10] == "4"
        }),
        "intercept_addr check failed: {}",
        rec_named
    );
    unsafe {
        libc::free(rec_named_ptr as *mut c_void);
    }
    let intercept_instr_named_unhook =
        unsafe { srx_inline_hook_unintercept(intercept_instr_named) };
    assert_eq!(
        intercept_instr_named_unhook, 0,
        "intercept_addr check failed"
    );
    unsafe {
        srx_inline_hook_set_recordable(false);
    }

    let intercept_func_stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            capi_intercept_target as *mut c_void,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(
        !intercept_func_stub.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    let intercept_func_dup = unsafe {
        srx_inline_hook_intercept_func_addr(
            capi_intercept_target as *mut c_void,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(intercept_func_dup.is_null(), "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        10,
        "intercept_addr check failed"
    );
    let intercept_func_unhook = unsafe { srx_inline_hook_unintercept(intercept_func_stub) };
    assert_eq!(intercept_func_unhook, 0, "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );

    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    let rec_reset = unsafe { srx_inline_hook_get_records(0x7FF) };
    if !rec_reset.is_null() {
        unsafe { libc::free(rec_reset as *mut c_void) };
    }
    let intercept_func_named = unsafe {
        srx_inline_hook_intercept_func_addr(
            capi_intercept_target as *mut c_void,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            4,
            c"named-func-lib.so".as_ptr(),
            c"named_intercept_target".as_ptr(),
        )
    };
    assert!(
        !intercept_func_named.is_null(),
        "intercept_addr check failed"
    );
    let rec_named_ptr = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(!rec_named_ptr.is_null(), "intercept_addr check failed");
    let rec_named = unsafe { core::ffi::CStr::from_ptr(rec_named_ptr) }
        .to_str()
        .expect("intercept_func_addr records utf8");
    assert!(
        rec_named.contains("named-func-lib.so"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.contains("named_intercept_target"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.contains("intercept_func_addr"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.lines().any(|line| {
            let cols: Vec<_> = line.split(',').collect();
            cols.len() >= 11 && cols[9].chars().all(|c| c.is_ascii_hexdigit())
        }),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.lines().any(|line| {
            let cols: Vec<_> = line.split(',').collect();
            cols.len() >= 11 && cols[10] == "4"
        }),
        "intercept_addr check failed: {}",
        rec_named
    );
    unsafe {
        libc::free(rec_named_ptr as *mut c_void);
    }
    let intercept_func_named_unhook = unsafe { srx_inline_hook_unintercept(intercept_func_named) };
    assert_eq!(
        intercept_func_named_unhook, 0,
        "intercept_addr check failed"
    );
    unsafe {
        srx_inline_hook_set_recordable(false);
    }

    let mut hook_orig = core::ptr::null_mut();
    let hook_func_stub = unsafe {
        srx_inline_hook_hook_func_addr(
            capi_intercept_target as *mut c_void,
            capi_hook_addr_replacement as *mut c_void,
            &mut hook_orig,
        )
    };
    assert!(!hook_func_stub.is_null(), "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    assert!(!hook_orig.is_null(), "intercept_addr check failed");
    let target_fn: extern "C" fn(i64, i64) -> i64 =
        unsafe { core::mem::transmute(capi_intercept_target as *const c_void) };
    assert_eq!(target_fn(3, 4), 707, "intercept_addr check failed");
    let hook_func_dup = unsafe {
        srx_inline_hook_hook_func_addr(
            capi_intercept_target as *mut c_void,
            capi_hook_addr_replacement as *mut c_void,
            core::ptr::null_mut(),
        )
    };
    assert!(hook_func_dup.is_null(), "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        16,
        "intercept_addr check failed"
    );
    let hook_func_unhook = unsafe { srx_inline_hook_unhook(hook_func_stub) };
    assert_eq!(hook_func_unhook, 0, "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    assert!(hook_orig.is_null(), "intercept_addr check failed");
    assert_eq!(target_fn(3, 4), 7, "intercept_addr check failed");

    let hook_sym_stub = unsafe {
        srx_inline_hook_hook_sym_addr(
            capi_intercept_target as *mut c_void,
            capi_hook_sym_replacement as *mut c_void,
            core::ptr::null_mut(),
        )
    };
    assert!(!hook_sym_stub.is_null(), "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    assert_eq!(target_fn(5, 6), 911, "intercept_addr check failed");
    let hook_sym_dup = unsafe {
        srx_inline_hook_hook_sym_addr(
            capi_intercept_target as *mut c_void,
            capi_hook_sym_replacement as *mut c_void,
            core::ptr::null_mut(),
        )
    };
    assert!(hook_sym_dup.is_null(), "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        16,
        "intercept_addr check failed"
    );
    let hook_sym_unhook = unsafe { srx_inline_hook_unhook(hook_sym_stub) };
    assert_eq!(hook_sym_unhook, 0, "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    assert_eq!(target_fn(5, 6), 11, "intercept_addr check failed");

    let strlen_handle = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!strlen_handle.is_null(), "intercept_addr check failed");
    let strlen_ptr = unsafe { libc::dlsym(strlen_handle, c"strlen".as_ptr()) };
    assert!(!strlen_ptr.is_null(), "intercept_addr check failed");
    let mut strlen_info: libc::Dl_info = unsafe { core::mem::zeroed() };
    assert_ne!(
        unsafe { libc::dladdr(strlen_ptr, &mut strlen_info) },
        0,
        "intercept_addr check failed"
    );
    assert!(
        !strlen_info.dli_fname.is_null(),
        "intercept_addr check failed"
    );

    let intercept_sym_addr_bad = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0x100,
        )
    };
    assert!(
        intercept_sym_addr_bad.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "intercept_addr check failed"
    );

    let intercept_sym_addr_stub = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(
        !intercept_sym_addr_stub.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    let intercept_sym_addr_dup = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(
        intercept_sym_addr_dup.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        10,
        "intercept_addr check failed"
    );
    let intercept_sym_addr_unhook = unsafe { srx_inline_hook_unintercept(intercept_sym_addr_stub) };
    assert_eq!(intercept_sym_addr_unhook, 0, "intercept_addr check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );

    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    let rec_reset = unsafe { srx_inline_hook_get_records(0x7FF) };
    if !rec_reset.is_null() {
        unsafe { libc::free(rec_reset as *mut c_void) };
    }
    let intercept_sym_addr_ro = unsafe {
        srx_inline_hook_intercept_sym_addr(
            strlen_ptr,
            capi_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            1 | 4,
            c"named-lib.so".as_ptr(),
            c"named_strlen".as_ptr(),
        )
    };
    assert!(
        !intercept_sym_addr_ro.is_null(),
        "intercept_addr check failed"
    );
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "intercept_addr check failed"
    );
    let rec_named_ptr = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(!rec_named_ptr.is_null(), "intercept_addr check failed");
    let rec_named = unsafe { core::ffi::CStr::from_ptr(rec_named_ptr) }
        .to_str()
        .expect("records named utf8");
    assert!(
        rec_named.contains("named-lib.so"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.contains("named_strlen"),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named.lines().any(|line| {
            let cols: Vec<_> = line.split(',').collect();
            cols.len() >= 11 && cols[9].chars().all(|c| c.is_ascii_hexdigit())
        }),
        "intercept_addr check failed: {}",
        rec_named
    );
    assert!(
        rec_named
            .lines()
            .any(|line| line.split(',').nth(10) == Some("5")),
        "intercept_addr check failed: {}",
        rec_named
    );
    unsafe {
        libc::free(rec_named_ptr as *mut c_void);
    }
    let intercept_sym_addr_ro_unhook =
        unsafe { srx_inline_hook_unintercept(intercept_sym_addr_ro) };
    assert_eq!(
        intercept_sym_addr_ro_unhook, 0,
        "intercept_addr check failed"
    );
    unsafe {
        srx_inline_hook_set_recordable(false);
    }
    unsafe { libc::dlclose(strlen_handle) };
    println!("capi_intercept_addr: PASS");
}
