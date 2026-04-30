// recordable 场景：开启后记录 hook / unhook 与 target 地址
// 额外覆盖 dump_records_with_items 字段过滤语义

use core::ffi::c_void;

use srx_inline_hook::{
    RecordItems, clear_records, dump_records, dump_records_with_items, hook_sym_name,
    is_recordable, set_recordable, unhook,
};

use crate::test_ctx::{STUB_ADD, clear, install, replacement_add, target_add};

pub fn recordable_dump() {
    // 开启前不应积累新记录
    set_recordable(false);
    assert!(!is_recordable());

    set_recordable(true);
    assert!(is_recordable());

    let stub = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(target_add(2, 3), 1005);
    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);

    let text = dump_records();
    assert!(
        text.contains("hook_func_addr"),
        "records check failed: {}",
        text
    );
    assert!(text.contains("unhook"), "records check failed: {}", text);
    let target_hex = format!("{:x}", target_add as *const () as usize);
    assert!(
        text.contains(&target_hex),
        "records check failed: {}, {}",
        target_hex,
        text
    );

    // items 过滤：仅 OP + ERRNO 时只保留两列 CSV
    let op_only = dump_records_with_items(RecordItems::OP | RecordItems::ERRNO);
    assert!(
        op_only.contains("hook_func_addr,0") && op_only.contains("unhook,0"),
        "records check failed: {}",
        op_only
    );
    assert!(
        !op_only.contains("target_add")
            && !op_only.contains("replacement_add")
            && !op_only.contains("hook-test,")
            && !op_only.contains("1970-")
            && !op_only.contains(&target_hex),
        "records check failed: {}",
        op_only
    );

    // 仅 SYM_ADDR：只留地址列；unhook 条目不输出该列
    let target_only = dump_records_with_items(RecordItems::SYM_ADDR);
    assert!(
        target_only.contains(&target_hex),
        "records check failed: {}",
        target_only
    );
    assert!(
        !target_only.contains("hook_func_addr") && !target_only.contains(",0"),
        "records check failed: {}",
        target_only
    );

    // LIB_NAME：target 地址走 dladdr 反查，本进程可执行 lib_path 应命中 hook-test
    let lib_only = dump_records_with_items(RecordItems::LIB_NAME);
    assert!(
        lib_only.contains("hook-test"),
        "records check failed: {}",
        lib_only
    );

    // BACKUP_LEN：hook 成功含 consumed 字节数；unhook 条目不含该列
    let backup_only = dump_records_with_items(RecordItems::BACKUP_LEN);
    assert!(
        backup_only
            .lines()
            .any(|line| !line.is_empty() && line != "0"),
        "records check failed: {}",
        backup_only
    );
    assert!(
        !backup_only.contains("hook_func_addr") && !backup_only.contains(&target_hex),
        "records check failed: {}",
        backup_only
    );

    let caller_only = dump_records_with_items(RecordItems::CALLER_LIB_NAME);
    assert!(
        caller_only.contains("hook-test"),
        "records check failed: {}",
        caller_only
    );

    let stub_only = dump_records_with_items(RecordItems::STUB);
    assert!(
        stub_only
            .lines()
            .any(|line| !line.is_empty() && line.chars().all(|c| c.is_ascii_hexdigit())),
        "records check failed: {}",
        stub_only
    );

    let flags_only = dump_records_with_items(RecordItems::FLAGS);
    assert!(
        flags_only.contains("0"),
        "records check failed: {}",
        flags_only
    );
    assert!(
        !flags_only.contains("unhook"),
        "records check failed: {}",
        flags_only
    );

    // ALL 等价于默认 dump_records
    let all = dump_records_with_items(RecordItems::ALL);
    assert_eq!(all, text, "records check failed");

    // clear_records 清空后 dump 为空；is_recordable 开关不受影响
    clear_records();
    assert!(is_recordable(), "records check failed");
    assert!(
        dump_records().is_empty(),
        "records check failed: {}",
        dump_records()
    );

    // hook_sym_name 仅产生 hook_sym_name 一条；不应再附带 hook_func_addr
    // SAFETY: libc.so / strlen 'static；replacement 为本 scenario 私有函数
    let sn_result = unsafe {
        hook_sym_name(
            c"libc.so",
            c"strlen",
            sn_replacement as *const core::ffi::c_void,
            core::ptr::null_mut(),
        )
    };
    if let Ok(stub) = sn_result {
        let sn_text = dump_records();
        assert!(
            sn_text.contains("hook_sym_name"),
            "records check failed: {}",
            sn_text
        );
        assert!(
            !sn_text.contains("hook_func_addr"),
            "records check failed: {}",
            sn_text
        );
        assert!(
            sn_text.contains("hook-test"),
            "records check failed: {}",
            sn_text
        );
        // SAFETY: stub 有效
        unsafe { unhook(stub).expect("unhook sym_name") };
    }
    clear_records();

    let intercept_stub = unsafe {
        srx_inline_hook_intercept_func_addr(
            record_intercept_target as *mut c_void,
            record_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            4,
            c"named-func-lib.so".as_ptr(),
            c"record_intercept_target".as_ptr(),
        )
    };
    assert!(!intercept_stub.is_null(), "records check failed");
    let intercept_text = dump_records();
    assert!(
        intercept_text.contains("intercept_func_addr"),
        "records check failed: {}",
        intercept_text
    );
    assert!(
        intercept_text.contains("named-func-lib.so")
            && intercept_text.contains("record_intercept_target"),
        "records check failed: {}",
        intercept_text
    );
    assert!(
        intercept_text.contains(",4"),
        "records check failed: {}",
        intercept_text
    );
    let intercept_unhook = unsafe { srx_inline_hook_unintercept(intercept_stub) };
    assert_eq!(intercept_unhook, 0, "records check failed");
    let unintercept_text = dump_records();
    assert!(
        unintercept_text.contains("unintercept"),
        "records check failed: {}",
        unintercept_text
    );
    clear_records();

    let handle = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    if !handle.is_null() {
        let strlen_ptr = unsafe { libc::dlsym(handle, c"strlen".as_ptr()) };
        if !strlen_ptr.is_null() {
            let intercept_sym_addr_stub = unsafe {
                srx_inline_hook_intercept_sym_addr(
                    strlen_ptr,
                    record_intercept_pre as *mut c_void,
                    core::ptr::null_mut(),
                    4,
                    c"named-lib.so".as_ptr(),
                    c"named_strlen".as_ptr(),
                )
            };
            if !intercept_sym_addr_stub.is_null() {
                let intercept_sym_addr_text = dump_records();
                assert!(
                    intercept_sym_addr_text.contains("intercept_sym_addr"),
                    "records check failed: {}",
                    intercept_sym_addr_text
                );
                assert!(
                    intercept_sym_addr_text.contains("named-lib.so")
                        && intercept_sym_addr_text.contains("named_strlen"),
                    "records check failed: {}",
                    intercept_sym_addr_text
                );
                assert!(
                    intercept_sym_addr_text.contains("4"),
                    "records check failed: {}",
                    intercept_sym_addr_text
                );
                assert!(
                    !intercept_sym_addr_text.contains("intercept_func_addr"),
                    "records check failed: {}",
                    intercept_sym_addr_text
                );
                let rc = unsafe { srx_inline_hook_unintercept(intercept_sym_addr_stub) };
                assert_eq!(rc, 0, "records check failed");

                clear_records();
                let intercept_sym_addr_path_stub = unsafe {
                    srx_inline_hook_intercept_sym_addr(
                        strlen_ptr,
                        record_intercept_pre as *mut c_void,
                        core::ptr::null_mut(),
                        4,
                        c"/system/lib64/named-lib.so".as_ptr(),
                        c"named_strlen".as_ptr(),
                    )
                };
                if !intercept_sym_addr_path_stub.is_null() {
                    let intercept_sym_addr_path_text = dump_records();
                    assert!(
                        intercept_sym_addr_path_text.contains("named-lib.so"),
                        "records check failed: {}",
                        intercept_sym_addr_path_text
                    );
                    assert!(
                        !intercept_sym_addr_path_text.contains("/system/lib64/named-lib.so"),
                        "records check failed: {}",
                        intercept_sym_addr_path_text
                    );
                    let rc = unsafe { srx_inline_hook_unintercept(intercept_sym_addr_path_stub) };
                    assert_eq!(rc, 0, "records check failed");
                }
            }
            clear_records();
        }
        unsafe { libc::dlclose(handle) };
    }

    let intercept_sym_stub = unsafe {
        srx_inline_hook_intercept_sym_name(
            c"libc.so".as_ptr(),
            c"strlen".as_ptr(),
            record_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    if !intercept_sym_stub.is_null() {
        let intercept_sym_text = dump_records();
        assert!(
            intercept_sym_text.contains("intercept_sym_name"),
            "records check failed: {}",
            intercept_sym_text
        );
        assert!(
            !intercept_sym_text.contains("intercept_func_addr"),
            "records check failed: {}",
            intercept_sym_text
        );
        assert!(
            intercept_sym_text.contains("hook-test"),
            "records check failed: {}",
            intercept_sym_text
        );
        let rc = unsafe { srx_inline_hook_unintercept(intercept_sym_stub) };
        assert_eq!(rc, 0, "records check failed");
    }
    clear_records();

    let pending_intercept_cb_stub = unsafe {
        srx_inline_hook_intercept_sym_name_callback(
            c"libctor_dtor_probe.so".as_ptr(),
            c"ctor_dtor_probe_add".as_ptr(),
            record_intercept_pre as *mut c_void,
            core::ptr::null_mut(),
            0,
            record_intercepted_cb as *mut c_void,
            core::ptr::null_mut(),
        )
    };
    assert!(!pending_intercept_cb_stub.is_null(), "records check failed");
    let pending_intercept_text = dump_records();
    assert!(
        pending_intercept_text.contains("intercept_sym_name")
            && pending_intercept_text.contains(",1,"),
        "records check failed: {}",
        pending_intercept_text
    );
    let pending_unhook = unsafe { srx_inline_hook_unintercept(pending_intercept_cb_stub) };
    assert_eq!(pending_unhook, -1, "records check failed");
    let pending_unintercept_text = dump_records();
    assert!(
        pending_unintercept_text.contains("unintercept")
            && pending_unintercept_text.contains(",33,"),
        "records check failed: {}",
        pending_unintercept_text
    );
    let pending_unintercept_caller = dump_records_with_items(
        RecordItems::CALLER_LIB_NAME | RecordItems::OP | RecordItems::ERRNO,
    );
    assert!(
        pending_unintercept_caller.contains("hook-test,unintercept,33"),
        "records check failed: {}",
        pending_unintercept_caller
    );
    clear_records();

    set_recordable(false);
    println!(
        "recordable_dump: PASS (full={}B op_only={}B target_only={}B lib_only={}B)",
        text.len(),
        op_only.len(),
        target_only.len(),
        lib_only.len()
    );
}

// 独立 replacement，避免跟其他 scenario 的 strlen hook 对比冲突
unsafe extern "C" {
    fn srx_inline_hook_intercept_func_addr(
        func_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_intercept_sym_addr(
        sym_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_intercept_sym_name(
        lib_name: *const core::ffi::c_char,
        sym_name: *const core::ffi::c_char,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
    ) -> *mut c_void;
    fn srx_inline_hook_intercept_sym_name_callback(
        lib_name: *const core::ffi::c_char,
        sym_name: *const core::ffi::c_char,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        intercepted: *mut c_void,
        intercepted_arg: *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_unintercept(stub: *mut c_void) -> i32;
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn record_intercept_target(a: i64, b: i64) -> i64 {
    std::hint::black_box(a).wrapping_add(std::hint::black_box(b))
}

extern "C" fn record_intercept_pre(_ctx: *mut c_void, _data: *mut c_void) {}

extern "C" fn record_intercepted_cb(
    _error: i32,
    _lib_name: *const core::ffi::c_char,
    _sym_name: *const core::ffi::c_char,
    _sym_addr: *const c_void,
    _pre: *mut c_void,
    _data: *mut c_void,
    _arg: *mut c_void,
) {
}

extern "C" fn sn_replacement(_s: *const core::ffi::c_char) -> usize {
    0
}
