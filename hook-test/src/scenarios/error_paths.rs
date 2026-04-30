// 错误路径：null / 不存在 so / 不存在 sym / 二次 unhook 的 errno 闭环
// 覆盖 hook_single / hook_sym_name 的参数校验与查表失败分支

use core::ffi::{CStr, c_void};
use core::ptr;

use srx_inline_hook::{
    Errno, clear_records, dump_records, errno_to_message, get_errno, hook_single, hook_sym_name,
    set_recordable, unhook,
};

pub fn error_paths() {
    clear_records();
    set_recordable(true);

    // 1) hook_single 传 null target
    // SAFETY: 显式构造 null 触发 InvalidArg 校验
    let r = unsafe { hook_single(ptr::null_mut(), 0x1 as *const c_void) };
    assert!(
        matches!(r, Err(Errno::InvalidArg)),
        "error_paths check failed: {:?}",
        r
    );

    // 2) hook_single 传 null replacement
    // SAFETY: target 非 null、replacement null 触发 InvalidArg
    let r = unsafe { hook_single(0x1 as *mut c_void, ptr::null()) };
    assert!(
        matches!(r, Err(Errno::InvalidArg)),
        "error_paths check failed: {:?}",
        r
    );

    // 3) hook_sym_name 不存在的 so：不算硬失败，应返回 pending stub + tls Pending(1)
    let bad_lib = CStr::from_bytes_with_nul(b"libsrx-inline-hook-nonexistent.so\0").unwrap();
    let any_sym = CStr::from_bytes_with_nul(b"strlen\0").unwrap();
    // SAFETY: replacement 非 null；参数有效性由 hook_sym_name 自校验
    let pending_stub = unsafe {
        hook_sym_name(
            bad_lib,
            any_sym,
            (error_paths as *const c_void).cast(),
            ptr::null_mut(),
        )
    }
    .expect("error_paths check failed");
    assert_eq!(get_errno(), Errno::Pending, "error_paths check failed");
    // SAFETY: 未完成 pending task 允许直接撤销，但返回 UnhookOnUnfinishedTask(33)
    let cancel = unsafe { unhook(pending_stub) };
    assert!(
        matches!(cancel, Err(Errno::UnhookOnUnfinishedTask)),
        "error_paths check failed: {:?}",
        cancel
    );

    // 4) hook_sym_name 存在的 so 但不存在的 sym：dlsym 失败映射为 DlSymFailed(18)
    let libc_name = CStr::from_bytes_with_nul(b"libc.so\0").unwrap();
    let ghost_sym = CStr::from_bytes_with_nul(b"srx_ghost_function_neverexist\0").unwrap();
    // SAFETY: libc 可加载；ghost_sym 必失败
    let r = unsafe {
        hook_sym_name(
            libc_name,
            ghost_sym,
            (error_paths as *const c_void).cast(),
            ptr::null_mut(),
        )
    };
    assert!(
        matches!(r, Err(Errno::DlSymFailed)),
        "error_paths check failed: {:?}",
        r
    );

    // 4.1) pending 任务命中已加载 so 但补装失败后，再撤销应返回 UnhookOnErrorTask(32)
    let missing_in_probe = CStr::from_bytes_with_nul(b"srx_missing_probe_symbol\0").unwrap();
    // SAFETY: 目标 so 初始未加载，应先返回 pending stub
    let broken_stub = unsafe {
        hook_sym_name(
            CStr::from_bytes_with_nul(b"libctor_dtor_probe.so\0").unwrap(),
            missing_in_probe,
            (error_paths as *const c_void).cast(),
            ptr::null_mut(),
        )
    }
    .expect("error_paths check failed");
    assert_eq!(get_errno(), Errno::Pending, "error_paths check failed");
    let handle = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "error_paths check failed");
    assert_eq!(get_errno(), Errno::Pending, "error_paths check failed");
    let cancel = unsafe { unhook(broken_stub) };
    assert!(
        matches!(cancel, Err(Errno::UnhookOnErrorTask)),
        "error_paths check failed: {:?}",
        cancel
    );
    let text = dump_records();
    assert!(
        text.contains("hook_sym_name") && text.contains(",18,"),
        "error_paths check failed: {}",
        text
    );
    assert!(
        text.contains("libctor_dtor_probe.so") && text.contains("srx_missing_probe_symbol"),
        "error_paths check failed: {}",
        text
    );
    unsafe { libc::dlclose(handle) };
    clear_records();

    // 4.5) 空串 lib_name 或 sym_name 先于 dlopen 挡回 InvalidArg
    let empty = CStr::from_bytes_with_nul(b"\0").unwrap();
    // SAFETY: CStr 空串触发前置参数校验
    let r = unsafe {
        hook_sym_name(
            empty,
            any_sym,
            (error_paths as *const c_void).cast(),
            ptr::null_mut(),
        )
    };
    assert!(
        matches!(r, Err(Errno::InvalidArg)),
        "error_paths check failed: {:?}",
        r
    );
    // SAFETY: 同上，空 sym_name
    let r = unsafe {
        hook_sym_name(
            libc_name,
            empty,
            (error_paths as *const c_void).cast(),
            ptr::null_mut(),
        )
    };
    assert!(
        matches!(r, Err(Errno::InvalidArg)),
        "error_paths check failed: {:?}",
        r
    );

    // 5) errno_to_message：i32 回环
    assert_eq!(errno_to_message(Errno::Ok as i32), "ok");
    assert_eq!(
        errno_to_message(Errno::InvalidArg as i32),
        "invalid argument"
    );
    assert_eq!(
        errno_to_message(Errno::HookOverlap as i32),
        "patch range overlaps an existing hook"
    );
    // 已补齐的上游码应返回稳定文案；未知码仍回 unknown
    assert_eq!(errno_to_message(9999), "unknown error number");
    assert_eq!(errno_to_message(Errno::NotSupport as i32), "not supported");
    assert_eq!(
        errno_to_message(Errno::MonitorDlopen as i32),
        "monitor dlopen failed"
    );
    assert_eq!(
        errno_to_message(Errno::HookIslandRewrite as i32),
        "alloc island for rewrite failed"
    );

    // Display 格式：{message} (errno={code})
    let shown = format!("{}", Errno::InvalidArg);
    assert_eq!(shown, "invalid argument (errno=3)");

    // std::error::Error 关联：via trait object 也能拿到 description
    let e: &dyn std::error::Error = &Errno::HookOverlap;
    assert_eq!(
        e.to_string(),
        "patch range overlaps an existing hook (errno=101)"
    );

    set_recordable(false);
    clear_records();
    println!("error_paths: PASS");
}
