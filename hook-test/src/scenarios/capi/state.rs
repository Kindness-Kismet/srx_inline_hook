use core::ffi::CStr;

use super::*;

pub(super) fn run() {
    // 1) version：常量字符串，NUL 终止
    // SAFETY: 返回进程生命期常量 c 字符串
    let ver_ptr = unsafe { srx_inline_hook_get_version() };
    assert!(!ver_ptr.is_null(), "state check failed");
    // SAFETY: ver_ptr 为 NUL 终止字符串
    let ver = unsafe { CStr::from_ptr(ver_ptr) }
        .to_str()
        .expect("version utf8");
    let expected_version = format!("srx_inline_hook version {}", env!("CARGO_PKG_VERSION"));
    assert_eq!(ver, expected_version, "state check failed");
    let expected_header = format!(
        "#define SRX_INLINE_HOOK_VERSION \"{}\"",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        SRX_INLINE_HOOK_HEADER_TEXT.contains(&expected_header),
        "state check failed"
    );

    // 2) init 幂等：主进程已 init 过，再调应回 Ok(0)
    // SAFETY: init 可重入
    let rc = unsafe {
        srx_inline_hook_init(1 /* UNIQUE */, false)
    };
    assert_eq!(rc, 0, "state check failed");
    // SAFETY: 读取原子初态
    assert_eq!(unsafe { srx_inline_hook_get_init_errno() }, 0);
    // SAFETY: 读取 MODE 原子
    assert_eq!(unsafe { srx_inline_hook_get_mode() }, 1);
    // SAFETY: get/set debuggable 与 disable 为原子状态读写
    let dbg_before = unsafe { srx_inline_hook_get_debuggable() };
    unsafe { srx_inline_hook_set_debuggable(!dbg_before) };
    assert_eq!(unsafe { srx_inline_hook_get_debuggable() }, !dbg_before);
    unsafe { srx_inline_hook_set_debuggable(dbg_before) };
    assert_eq!(unsafe { srx_inline_hook_get_debuggable() }, dbg_before);
    let disable_before = unsafe { srx_inline_hook_get_disable() };
    unsafe { srx_inline_hook_set_disable(!disable_before) };
    assert_eq!(unsafe { srx_inline_hook_get_disable() }, !disable_before);
    unsafe { srx_inline_hook_set_disable(disable_before) };
    assert_eq!(unsafe { srx_inline_hook_get_disable() }, disable_before);

    // 2.1) 非法 mode 应返回 InvalidArg(3)
    // SAFETY: 检查参数校验路径
    let bad_rc = unsafe { srx_inline_hook_init(7, false) };
    assert_eq!(bad_rc, 3, "state check failed: {}", bad_rc);
    // SAFETY: bad init 不应污染已成功的 init_errno
    assert_eq!(unsafe { srx_inline_hook_get_init_errno() }, 0);

    unsafe { srx_inline_hook_set_disable(true) };
    assert!(
        unsafe { srx_inline_hook_get_disable() },
        "state check failed"
    );
    let disabled_hook = unsafe {
        srx_inline_hook_hook_func_addr(
            capi_intercept_target as *mut c_void,
            capi_hook_addr_replacement as *mut c_void,
            ptr::null_mut(),
        )
    };
    assert!(disabled_hook.is_null(), "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    let disabled_intercept = unsafe {
        srx_inline_hook_intercept_func_addr(
            capi_intercept_target as *mut c_void,
            capi_intercepted_cb as *mut c_void,
            ptr::null_mut(),
            0,
        )
    };
    assert!(disabled_intercept.is_null(), "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    let disabled_unhook = unsafe { srx_inline_hook_unhook(0x1 as *mut c_void) };
    assert_eq!(disabled_unhook, -1, "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    let disabled_unintercept = unsafe { srx_inline_hook_unintercept(0x1 as *mut c_void) };
    assert_eq!(disabled_unintercept, -1, "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    let disabled_dl_cb = unsafe {
        srx_inline_hook_register_dl_init_callback(
            capi_hook_addr_replacement as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(disabled_dl_cb, 45, "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    let disabled_dl_unreg = unsafe {
        srx_inline_hook_unregister_dl_init_callback(
            capi_hook_addr_replacement as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(disabled_dl_unreg, 45, "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    let disabled_fini_reg = unsafe {
        srx_inline_hook_register_dl_fini_callback(
            capi_hook_addr_replacement as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(disabled_fini_reg, 45, "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    let disabled_fini_unreg = unsafe {
        srx_inline_hook_unregister_dl_fini_callback(
            capi_hook_addr_replacement as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(disabled_fini_unreg, 45, "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        45,
        "state check failed"
    );
    unsafe { srx_inline_hook_set_disable(false) };
    assert!(
        !unsafe { srx_inline_hook_get_disable() },
        "state check failed"
    );

    // 2.2) capi NULL 校验写 tls_errno = InvalidArg 并返 NULL
    // SAFETY: 故意 NULL 触发前置校验
    let null_stub = unsafe {
        srx_inline_hook_hook_sym_name(ptr::null(), ptr::null(), ptr::null_mut(), ptr::null_mut())
    };
    assert!(null_stub.is_null(), "state check failed");
    // SAFETY: get_errno 必须读到 InvalidArg(3)
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "state check failed"
    );

    // 2.3) _unhook(NULL)：返 -1，tls_errno = InvalidArg(3)
    // SAFETY: 显式 NULL 触发前置校验
    let null_unhook = unsafe { srx_inline_hook_unhook(ptr::null_mut()) };
    assert_eq!(null_unhook, -1, "state check failed");
    // SAFETY: 读 tls_errno
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "state check failed"
    );

    // 3) to_errmsg：0-45 全量按上游 sh_errno.c 运行时文案对齐
    let expected_errmsg = [
        (0, "OK"),
        (1, "Pending task"),
        (2, "Not initialized"),
        (3, "Invalid argument"),
        (4, "Out of memory"),
        (5, "MProtect failed"),
        (6, "Write to arbitrary address crashed"),
        (7, "Init errno mod failed"),
        (8, "Init bytesig mod SIGSEGV failed"),
        (9, "Init bytesig mod SIGBUS failed"),
        (10, "Duplicate intercept"),
        (11, "Init safe mod failed"),
        (12, "Init linker mod failed"),
        (13, "Init hub mod failed"),
        (14, "Create hub failed"),
        (15, "Monitor dlopen failed"),
        (16, "Duplicate shared hook"),
        (17, "Open ELF crashed"),
        (18, "Find symbol in ELF failed"),
        (19, "Find symbol in ELF crashed"),
        (20, "Duplicate unique ook"),
        (21, "Dladdr crashed"),
        (22, "Find dlinfo failed"),
        (23, "Symbol size too small"),
        (24, "Alloc enter failed"),
        (25, "Instruction rewrite crashed"),
        (26, "Instruction rewrite failed"),
        (27, "Unop not found"),
        (28, "Verify original instruction crashed"),
        (29, "Verify original instruction failed"),
        (30, "Verify exit instruction failed"),
        (31, "Verify exit instruction crashed"),
        (32, "Unop on an error status task"),
        (33, "Unop on an unfinished task"),
        (34, "ELF with an unsupported architecture"),
        (35, "Linker with an unsupported architecture"),
        (36, "Duplicate init fini callback"),
        (37, "Unregister not-existed init fini callback"),
        (38, "Register callback not supported"),
        (39, "Init task mod failed"),
        (40, "Alloc island for exit failed"),
        (41, "Alloc island for enter failed"),
        (42, "Alloc island for rewrite failed"),
        (43, "Mode conflict"),
        (44, "Duplicate multi hook"),
        (45, "Disabled"),
    ];
    for (code, expected) in expected_errmsg {
        let actual = unsafe { CStr::from_ptr(srx_inline_hook_to_errmsg(code)) }
            .to_str()
            .expect("errmsg utf8");
        assert_eq!(actual, expected, "state check failed: {}, {}", code, actual);
    }
    let overlap_msg = unsafe { CStr::from_ptr(srx_inline_hook_to_errmsg(101)) }
        .to_str()
        .expect("overlap errmsg utf8");
    assert_eq!(
        overlap_msg, "Patch range overlaps an existing hook",
        "state check failed"
    );

    let overlap_stub_a = unsafe {
        srx_inline_hook_hook_func_addr(
            capi_overlap_a as *mut c_void,
            capi_overlap_replacement as *mut c_void,
            ptr::null_mut(),
        )
    };
    assert!(!overlap_stub_a.is_null(), "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "state check failed"
    );
    let overlap_stub_b = unsafe {
        srx_inline_hook_hook_func_addr(
            capi_overlap_b as *mut c_void,
            capi_overlap_replacement as *mut c_void,
            ptr::null_mut(),
        )
    };
    assert!(overlap_stub_b.is_null(), "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        101,
        "state check failed"
    );
    let overlap_unhook = unsafe { srx_inline_hook_unhook(overlap_stub_a) };
    assert_eq!(overlap_unhook, 0, "state check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "state check failed"
    );

    println!("capi_state: PASS");
}
