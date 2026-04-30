use super::*;

pub(super) fn run() {
    let libc_name = c"libc.so";
    let sym_name = c"strlen";
    let strlen_handle = unsafe { libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOW) };
    assert!(!strlen_handle.is_null(), "lookup_flags check failed");
    let strlen_ptr = unsafe { libc::dlsym(strlen_handle, sym_name.as_ptr()) };
    assert!(!strlen_ptr.is_null(), "lookup_flags check failed");
    let mut strlen_info: libc::Dl_info = unsafe { core::mem::zeroed() };
    assert_ne!(
        unsafe { libc::dladdr(strlen_ptr, &mut strlen_info) },
        0,
        "lookup_flags check failed"
    );
    assert!(
        !strlen_info.dli_fname.is_null(),
        "lookup_flags check failed"
    );
    let libc_path = unsafe { core::ffi::CStr::from_ptr(strlen_info.dli_fname) };
    // 7) 新线程未调任何 API 时 _get_errno() 返回 0
    //    pthread_getspecific 未 set 时返 NULL → 0 的语义
    let fresh_errno = std::thread::spawn(|| {
        // SAFETY: get_errno 只读线程局部槽
        unsafe { srx_inline_hook_get_errno() }
    })
    .join()
    .expect("fresh thread join");
    assert_eq!(fresh_errno, 0, "lookup_flags check failed: {}", fresh_errno);

    // dlopen / dlsym / dlclose 覆盖 dynsym 与 symtab 回退
    // SAFETY: libc_name 为 'static CStr
    let dl_handle = unsafe { srx_inline_hook_dlopen(libc_name.as_ptr()) };
    assert!(!dl_handle.is_null(), "lookup_flags check failed");
    // SAFETY: handle 有效；sym_name 为 'static CStr
    let dl_strlen = unsafe { srx_inline_hook_dlsym(dl_handle, sym_name.as_ptr()) };
    assert!(!dl_strlen.is_null(), "lookup_flags check failed");
    let dl_strlen_lit = unsafe { srx_inline_hook_dlsym(dl_handle, c"strlen".as_ptr()) };
    assert_eq!(dl_strlen_lit, dl_strlen, "lookup_flags check failed");
    // SAFETY: dynsym 变体只查动态符号表
    let dl_strlen_dyn = unsafe { srx_inline_hook_dlsym_dynsym(dl_handle, sym_name.as_ptr()) };
    assert_eq!(dl_strlen_dyn, dl_strlen, "lookup_flags check failed");
    // SAFETY: symtab 变体应能从 libc.so 的 ELF symtab 查到 strlen
    let dl_strlen_st = unsafe { srx_inline_hook_dlsym_symtab(dl_handle, sym_name.as_ptr()) };
    assert!(!dl_strlen_st.is_null(), "lookup_flags check failed");
    // SAFETY: probe so 与主程序同目录
    let probe_handle = unsafe { srx_inline_hook_dlopen(c"./libctor_dtor_probe.so".as_ptr()) };
    assert!(!probe_handle.is_null(), "lookup_flags check failed");
    let probe_helper = unsafe {
        srx_inline_hook_dlsym(probe_handle, c"ctor_dtor_probe_symtab_only_addr".as_ptr())
    };
    assert!(!probe_helper.is_null(), "lookup_flags check failed");
    let probe_helper_fn: extern "C" fn() -> *mut c_void =
        unsafe { core::mem::transmute(probe_helper) };
    let probe_symtab_expected = probe_helper_fn();
    assert!(
        !probe_symtab_expected.is_null(),
        "lookup_flags check failed"
    );
    let probe_symtab_only =
        unsafe { srx_inline_hook_dlsym(probe_handle, c"ctor_dtor_probe_symtab_only".as_ptr()) };
    let probe_symtab_dyn = unsafe {
        srx_inline_hook_dlsym_dynsym(probe_handle, c"ctor_dtor_probe_symtab_only".as_ptr())
    };
    let probe_symtab_st = unsafe {
        srx_inline_hook_dlsym_symtab(probe_handle, c"ctor_dtor_probe_symtab_only".as_ptr())
    };
    assert!(probe_symtab_dyn.is_null(), "lookup_flags check failed");
    assert_eq!(
        probe_symtab_st, probe_symtab_expected,
        "lookup_flags check failed"
    );
    assert_eq!(
        probe_symtab_only, probe_symtab_st,
        "lookup_flags check failed"
    );

    let debugdata_handle = unsafe { srx_inline_hook_dlopen(c"libm.so".as_ptr()) };
    assert!(!debugdata_handle.is_null(), "lookup_flags check failed");
    let debugdata_dyn =
        unsafe { srx_inline_hook_dlsym_dynsym(debugdata_handle, c"large_gam".as_ptr()) };
    let debugdata_st =
        unsafe { srx_inline_hook_dlsym_symtab(debugdata_handle, c"large_gam".as_ptr()) };
    let debugdata_any = unsafe { srx_inline_hook_dlsym(debugdata_handle, c"large_gam".as_ptr()) };
    if debugdata_st.is_null() {
        assert!(
            debugdata_dyn.is_null() && debugdata_any.is_null(),
            "lookup_flags check failed"
        );
    } else {
        assert!(debugdata_dyn.is_null(), "lookup_flags check failed");
        assert_eq!(debugdata_any, debugdata_st, "lookup_flags check failed");
    }

    // SAFETY: NULL handle 短路
    let null_sym = unsafe { srx_inline_hook_dlsym(core::ptr::null_mut(), sym_name.as_ptr()) };
    assert!(null_sym.is_null(), "lookup_flags check failed");
    // SAFETY: NULL lib_name 短路
    let null_h = unsafe { srx_inline_hook_dlopen(core::ptr::null()) };
    assert!(null_h.is_null(), "lookup_flags check failed");
    // SAFETY: handle 来自 _dlopen
    unsafe {
        srx_inline_hook_dlclose(debugdata_handle);
        srx_inline_hook_dlclose(probe_handle);
        srx_inline_hook_dlclose(dl_handle);
    }

    // hook_sym_name_2 覆盖 Shared / Multi / Unique 与非法 flags
    // Multi 模式要求 orig_addr 非空，非法高位返回 InvalidArg(3)
    let shared_stub = unsafe {
        srx_inline_hook_hook_sym_name_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            core::ptr::null_mut(),
            1, // SRX_INLINE_HOOK_HOOK_WITH_SHARED_MODE
        )
    };
    assert!(!shared_stub.is_null(), "lookup_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "lookup_flags check failed"
    );
    let shared_unhook = unsafe { srx_inline_hook_unhook(shared_stub) };
    assert_eq!(shared_unhook, 0, "lookup_flags check failed");
    let multi_null_orig = unsafe {
        srx_inline_hook_hook_sym_name_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            core::ptr::null_mut(),
            4, // SRX_INLINE_HOOK_HOOK_WITH_MULTI_MODE
        )
    };
    assert!(multi_null_orig.is_null(), "lookup_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "lookup_flags check failed"
    );
    let mut multi_orig = core::ptr::null_mut();
    let multi_stub = unsafe {
        srx_inline_hook_hook_sym_name_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            &mut multi_orig,
            4, // SRX_INLINE_HOOK_HOOK_WITH_MULTI_MODE
        )
    };
    assert!(!multi_stub.is_null(), "lookup_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "lookup_flags check failed"
    );
    assert!(!multi_orig.is_null(), "lookup_flags check failed");
    // 清理 MULTI hook 恢复状态
    // SAFETY: multi_stub 来自上一次 _hook_sym_name_2
    let multi_unhook = unsafe { srx_inline_hook_unhook(multi_stub) };
    assert_eq!(multi_unhook, 0, "lookup_flags check failed");
    // SAFETY: 非法高位
    let bad_stub = unsafe {
        srx_inline_hook_hook_sym_name_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            core::ptr::null_mut(),
            0x100,
        )
    };
    assert!(bad_stub.is_null(), "lookup_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "lookup_flags check failed"
    );
    // SAFETY: flags=0 走标准路径
    let ok_stub = unsafe {
        srx_inline_hook_hook_sym_name_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    if !ok_stub.is_null() {
        unsafe {
            CAPI_STUB = ok_stub;
        }
        // 命中一次再 unhook
        let probe_h = c"flag2";
        // SAFETY: strlen_ptr 指向 libc
        let _ = unsafe {
            let f: StrlenFn = core::mem::transmute(strlen_ptr);
            f(probe_h.as_ptr())
        };
        // SAFETY: stub 有效
        let urc = unsafe { srx_inline_hook_unhook(ok_stub) };
        assert_eq!(urc, 0, "lookup_flags check failed");
        unsafe {
            CAPI_STUB = core::ptr::null_mut();
        }
    }

    let path_stub = unsafe {
        srx_inline_hook_hook_sym_name_2(
            libc_path.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    assert!(!path_stub.is_null(), "lookup_flags check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "lookup_flags check failed"
    );
    let path_probe = c"path";
    let path_hooked_len = unsafe {
        let f: StrlenFn = core::mem::transmute(strlen_ptr);
        f(path_probe.as_ptr())
    };
    assert_eq!(path_hooked_len, 4 + 500, "lookup_flags check failed");
    let path_unhook = unsafe { srx_inline_hook_unhook(path_stub) };
    assert_eq!(path_unhook, 0, "lookup_flags check failed");
    let restored_len = unsafe {
        let f: StrlenFn = core::mem::transmute(strlen_ptr);
        f(path_probe.as_ptr())
    };
    assert_eq!(restored_len, 4, "lookup_flags check failed");
    unsafe { libc::dlclose(strlen_handle) };

    println!("capi_lookup_flags: PASS");
}
