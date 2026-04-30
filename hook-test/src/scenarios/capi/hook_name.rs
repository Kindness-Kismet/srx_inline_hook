use super::*;

pub(super) fn run() {
    // 4) hook_sym_name_2(shared)：端到端验证 C API 打通
    let libc_name = c"libc.so";
    let sym_name = c"strlen";
    // dlopen/dlsym 拿真实 strlen 入口：走函数指针调用，避免 LLVM 常量折叠 strlen("...")
    // SAFETY: CStr 为 'static；dlopen 仅返回 handle
    let handle = unsafe { libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        println!("capi_hook_name: skipped");
        return;
    }
    // SAFETY: handle 来自 dlopen；sym_name 为 'static CStr
    let strlen_ptr = unsafe { libc::dlsym(handle, sym_name.as_ptr()) };
    if strlen_ptr.is_null() {
        println!("capi_hook_name: skipped");
        return;
    }
    let mut strlen_info: libc::Dl_info = unsafe { core::mem::zeroed() };
    let strlen_dladdr = unsafe { libc::dladdr(strlen_ptr, &mut strlen_info) };
    if strlen_dladdr == 0 || strlen_info.dli_fname.is_null() {
        println!("capi_hook_name: skipped");
        return;
    }

    // SAFETY: CStr 为 'static；new_addr 为本进程代码指针
    let stub = unsafe {
        srx_inline_hook_hook_sym_name_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            core::ptr::null_mut(),
            1,
        )
    };
    if stub.is_null() {
        // SAFETY: 读 tls_errno
        let err = unsafe { srx_inline_hook_get_errno() };
        println!("capi_hook_name: SKIP (hook_sym_name fail errno={})", err);
        return;
    }
    unsafe {
        CAPI_STUB = stub;
    }

    // 走一次 strlen：应命中 replacement 返回 real + 500
    let probe = c"capi-hi";
    // SAFETY: strlen_ptr 指向 libc 可执行代码；ABI 与 C strlen 一致
    let hooked_len = unsafe {
        let f: StrlenFn = core::mem::transmute(strlen_ptr);
        f(probe.as_ptr())
    };
    assert_eq!(hooked_len, 7 + 500, "hook_name check failed");

    // 5) recordable + get_records：开启后应有新记录产生（hook_sym_name 本身一条）
    // SAFETY: 原子开关
    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    // SAFETY: 原子读
    assert!(unsafe { srx_inline_hook_get_recordable() });

    // 触发一次 unhook 事件进记录
    // SAFETY: stub 来自 _hook_sym_name
    let unhook_rc = unsafe { srx_inline_hook_unhook(stub) };
    assert_eq!(unhook_rc, 0, "hook_name check failed");
    unsafe {
        CAPI_STUB = core::ptr::null_mut();
    }

    // get_records: ALL=0x7FF 应返回完整记录项文本
    // SAFETY: 返回堆分配 C 字符串，配对 free_records 释放
    let recs_ptr = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(!recs_ptr.is_null(), "hook_name check failed");
    // SAFETY: recs_ptr 为 NUL 终止
    let recs = unsafe { core::ffi::CStr::from_ptr(recs_ptr) }
        .to_str()
        .expect("records utf8");
    assert!(recs.contains("unhook"), "hook_name check failed: {}", recs);
    // SAFETY: recs_ptr 来自 _get_records；用对应 free_records 释放
    unsafe {
        libc::free(recs_ptr as *mut c_void);
    }

    // get_records 返回 libc::malloc 内存，C 侧可直接 free()
    // SAFETY: 同前，参数为 RECORD_ITEM_ALL
    let recs_ptr2 = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(!recs_ptr2.is_null(), "hook_name check failed");
    // SAFETY: recs_ptr2 来自 libc::malloc，与 C 标准 free 兼容
    unsafe {
        libc::free(recs_ptr2 as *mut c_void);
    }

    // 关 recordable 复位
    // SAFETY: 原子开关
    unsafe {
        srx_inline_hook_set_recordable(false);
    }

    // 5.1) !recordable 时 get_records 返 NULL
    // SAFETY: recordable=false 关闭后立即查询
    let null_recs = unsafe { srx_inline_hook_get_records(0x7FF) };
    assert!(null_recs.is_null(), "hook_name check failed");
    // 5.2) 仅传 CALLER_LIB_NAME / STUB / FLAGS 也应返回真实文本
    // SAFETY: 打开 recordable 以排除 5.1 的归因歧义
    unsafe {
        srx_inline_hook_set_recordable(true);
    }
    let extra_only = (1u32 << 1) | (1u32 << 9) | (1u32 << 10);
    let empty_items = unsafe { srx_inline_hook_get_records(0) };
    assert!(empty_items.is_null(), "hook_name check failed");
    let unknown_only = unsafe { srx_inline_hook_get_records(1u32 << 31) };
    assert!(unknown_only.is_null(), "hook_name check failed");
    let recs_ptr3 = unsafe { srx_inline_hook_get_records(extra_only) };
    assert!(!recs_ptr3.is_null(), "hook_name check failed");
    let mixed_items = extra_only | (1u32 << 31);
    let recs_ptr4 = unsafe { srx_inline_hook_get_records(mixed_items) };
    assert!(!recs_ptr4.is_null(), "hook_name check failed");
    let recs3 = unsafe { core::ffi::CStr::from_ptr(recs_ptr3) }
        .to_str()
        .expect("records extra utf8");
    let recs4 = unsafe { core::ffi::CStr::from_ptr(recs_ptr4) }
        .to_str()
        .expect("records mixed utf8");
    assert!(
        recs3.contains("hook-test"),
        "hook_name check failed: {}",
        recs3
    );
    assert_eq!(recs4, recs3, "hook_name check failed");
    assert!(
        recs3.lines().any(|line| {
            let cols: Vec<_> = line.split(',').collect();
            cols.len() >= 2 && cols[1].chars().all(|c| c.is_ascii_hexdigit())
        }),
        "hook_name check failed: {}",
        recs3
    );
    unsafe { srx_inline_hook_dump_records(-1, mixed_items) };
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_name check failed"
    );
    unsafe { srx_inline_hook_dump_records(1, 0) };
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_name check failed"
    );
    unsafe { srx_inline_hook_dump_records(1, 1u32 << 31) };
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_name check failed"
    );
    unsafe {
        libc::free(recs_ptr3 as *mut c_void);
        libc::free(recs_ptr4 as *mut c_void);
        srx_inline_hook_set_recordable(false);
    }

    // 6) hook_sym_name_callback：调用 hooked 回调一次，error 应为 0
    let mut cb_error: c_int = -1;
    let mut orig_slot: *mut c_void = core::ptr::null_mut();
    let orig_slot_addr = &mut orig_slot as *mut *mut c_void;
    // 复位 cb 观察槽
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    CAPI_CB_SYM.store(core::ptr::null_mut(), Ordering::Release);
    CAPI_CB_NEW_ADDR.store(core::ptr::null_mut(), Ordering::Release);
    CAPI_CB_ARG.store(core::ptr::null_mut(), Ordering::Release);
    *CAPI_CB_LIB_NAME_TEXT.lock().expect("reset hook cb lib") = None;
    *CAPI_CB_SYM_NAME_TEXT.lock().expect("reset hook cb sym") = None;
    // SAFETY: 同 hook_sym_name
    let stub2 = unsafe {
        srx_inline_hook_hook_sym_name_callback(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            orig_slot_addr,
            Some(capi_hooked_cb),
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    if stub2.is_null() {
        // SAFETY: 读 tls_errno
        let err = unsafe { srx_inline_hook_get_errno() };
        println!(
            "capi_hook_name: PARTIAL (sym_name_callback fail errno={})",
            err
        );
        return;
    }
    unsafe {
        CAPI_STUB = stub2;
    }
    assert_eq!(cb_error, 0, "hook_name check failed: {}", cb_error);
    let seen_lib = CAPI_CB_LIB_NAME_TEXT
        .lock()
        .expect("read hook cb lib")
        .clone()
        .expect("hook cb lib set");
    let seen_sym = CAPI_CB_SYM_NAME_TEXT
        .lock()
        .expect("read hook cb sym")
        .clone()
        .expect("hook cb sym set");
    assert_eq!(seen_lib, "libc.so", "hook_name check failed");
    assert_eq!(seen_sym, "strlen", "hook_name check failed");
    assert_eq!(
        CAPI_CB_ARG.load(Ordering::Acquire),
        &mut cb_error as *mut c_int as *mut c_void,
        "hook_name check failed"
    );
    assert_eq!(
        CAPI_CB_NEW_ADDR.load(Ordering::Acquire),
        replacement_capi_strlen as *mut c_void,
        "hook_name check failed"
    );
    assert!(
        !CAPI_CB_SYM.load(Ordering::Acquire).is_null(),
        "hook_name check failed"
    );
    // orig_addr 参数 = 用户传入的槽位指针本身
    let seen_orig = CAPI_CB_ORIG_ADDR.load(core::sync::atomic::Ordering::Acquire);
    assert_eq!(
        seen_orig as *const c_void, orig_slot_addr as *const c_void,
        "hook_name check failed"
    );
    cb_error = -1;
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    CAPI_CB_SYM.store(core::ptr::null_mut(), Ordering::Release);
    CAPI_CB_NEW_ADDR.store(core::ptr::null_mut(), Ordering::Release);
    let stub2_dup = unsafe {
        srx_inline_hook_hook_sym_name_callback(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            replacement_capi_strlen as *mut c_void,
            orig_slot_addr,
            Some(capi_hooked_cb),
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    assert!(stub2_dup.is_null(), "hook_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        16,
        "hook_name check failed"
    );
    assert_ne!(cb_error, -1, "hook_name check failed");
    assert_eq!(cb_error, 16, "hook_name check failed");
    assert_eq!(
        CAPI_CB_NEW_ADDR.load(Ordering::Acquire),
        replacement_capi_strlen as *mut c_void,
        "hook_name check failed"
    );
    assert!(
        !CAPI_CB_SYM.load(Ordering::Acquire).is_null(),
        "hook_name check failed"
    );
    assert_eq!(
        CAPI_CB_ORIG_ADDR.load(core::sync::atomic::Ordering::Acquire),
        orig_slot_addr as *mut c_void,
        "hook_name check failed"
    );
    // SAFETY: stub2 有效
    let rc2 = unsafe { srx_inline_hook_unhook(stub2) };
    assert_eq!(rc2, 0);
    unsafe {
        CAPI_STUB = core::ptr::null_mut();
    }

    // callback 可为 NULL：成功路径仍应安装成功，且不触发回调写槽
    cb_error = -1;
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    let stub2_null_cb = unsafe {
        srx_inline_hook_hook_sym_name_callback(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            orig_slot_addr,
            None,
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    assert!(!stub2_null_cb.is_null(), "hook_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_name check failed"
    );
    assert_eq!(cb_error, -1, "hook_name check failed");
    assert_eq!(
        CAPI_CB_ORIG_ADDR.load(core::sync::atomic::Ordering::Acquire),
        core::ptr::null_mut(),
        "hook_name check failed"
    );
    let rc2_null_cb = unsafe { srx_inline_hook_unhook(stub2_null_cb) };
    assert_eq!(rc2_null_cb, 0, "hook_name check failed");

    cb_error = -1;
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    let bad_stub2 = unsafe {
        srx_inline_hook_hook_sym_name_callback_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            orig_slot_addr,
            0x100,
            Some(capi_hooked_cb),
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    assert!(bad_stub2.is_null(), "hook_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "hook_name check failed"
    );
    assert_eq!(cb_error, -1, "hook_name check failed");

    cb_error = -1;
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    let multi_cb_null_orig = unsafe {
        srx_inline_hook_hook_sym_name_callback_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            core::ptr::null_mut(),
            4,
            Some(capi_hooked_cb),
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    assert!(multi_cb_null_orig.is_null(), "hook_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        3,
        "hook_name check failed"
    );
    assert_eq!(cb_error, -1, "hook_name check failed");

    cb_error = -1;
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    CAPI_CB_NEW_ADDR.store(core::ptr::null_mut(), Ordering::Release);
    let stub2_flags = unsafe {
        srx_inline_hook_hook_sym_name_callback_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            orig_slot_addr,
            2,
            Some(capi_hooked_cb),
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    assert!(!stub2_flags.is_null(), "hook_name check failed");
    unsafe {
        CAPI_STUB = stub2_flags;
    }
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_name check failed"
    );
    assert_eq!(cb_error, 0, "hook_name check failed");
    assert_eq!(
        CAPI_CB_NEW_ADDR.load(Ordering::Acquire),
        replacement_capi_strlen as *mut c_void,
        "hook_name check failed"
    );
    assert!(
        !CAPI_CB_SYM.load(Ordering::Acquire).is_null(),
        "hook_name check failed"
    );
    assert_eq!(
        CAPI_CB_ORIG_ADDR.load(core::sync::atomic::Ordering::Acquire),
        orig_slot_addr as *mut c_void,
        "hook_name check failed"
    );

    cb_error = -1;
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    CAPI_CB_SYM.store(core::ptr::null_mut(), Ordering::Release);
    CAPI_CB_NEW_ADDR.store(core::ptr::null_mut(), Ordering::Release);
    let stub2_flags_dup = unsafe {
        srx_inline_hook_hook_sym_name_callback_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            orig_slot_addr,
            2,
            Some(capi_hooked_cb),
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    assert!(stub2_flags_dup.is_null(), "hook_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        16,
        "hook_name check failed"
    );
    assert_ne!(cb_error, -1, "hook_name check failed");
    assert_eq!(cb_error, 16, "hook_name check failed");
    assert_eq!(
        CAPI_CB_NEW_ADDR.load(Ordering::Acquire),
        replacement_capi_strlen as *mut c_void,
        "hook_name check failed"
    );
    assert!(
        !CAPI_CB_SYM.load(Ordering::Acquire).is_null(),
        "hook_name check failed"
    );
    assert_eq!(
        CAPI_CB_ORIG_ADDR.load(core::sync::atomic::Ordering::Acquire),
        orig_slot_addr as *mut c_void,
        "hook_name check failed"
    );
    let rc2_flags = unsafe { srx_inline_hook_unhook(stub2_flags) };
    assert_eq!(rc2_flags, 0, "hook_name check failed");
    unsafe {
        CAPI_STUB = core::ptr::null_mut();
    }

    cb_error = -1;
    CAPI_CB_ORIG_ADDR.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    let stub2_flags_null_cb = unsafe {
        srx_inline_hook_hook_sym_name_callback_2(
            libc_name.as_ptr(),
            sym_name.as_ptr(),
            replacement_capi_strlen as *mut c_void,
            orig_slot_addr,
            2,
            None,
            &mut cb_error as *mut c_int as *mut c_void,
        )
    };
    assert!(!stub2_flags_null_cb.is_null(), "hook_name check failed");
    assert_eq!(
        unsafe { srx_inline_hook_get_errno() },
        0,
        "hook_name check failed"
    );
    assert_eq!(cb_error, -1, "hook_name check failed");
    assert_eq!(
        CAPI_CB_ORIG_ADDR.load(core::sync::atomic::Ordering::Acquire),
        core::ptr::null_mut(),
        "hook_name check failed"
    );
    let rc2_flags_null_cb = unsafe { srx_inline_hook_unhook(stub2_flags_null_cb) };
    assert_eq!(rc2_flags_null_cb, 0, "hook_name check failed");

    // dump_to_fd 走一次：确保符号可解析；fd=-1 触发 InvalidArg 路径但 capi 只忽略返回
    // SAFETY: 原子只读且幂等
    unsafe {
        srx_inline_hook_dump_records(-1, 0x7FF);
    }
    println!("capi_hook_name: PASS");
}
