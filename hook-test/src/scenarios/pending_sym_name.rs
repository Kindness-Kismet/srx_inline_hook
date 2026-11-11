// pending hook：目标 so 未加载时返回 Pending，后续 dlopen 命中自动安装
// 用 libctor_dtor_probe.so 验证 ctor pre 补装，覆盖 orig_slot / callback / unhook

use core::ffi::{c_char, c_int, c_void};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};

use srx_inline_hook::{Errno, get_errno, hook_sym_name, hook_sym_name_callback, unhook};

type AddFn = unsafe extern "C" fn(c_int, c_int) -> c_int;

static ORIG_ADD: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CALLBACK_HITS: AtomicU32 = AtomicU32::new(0);
static CALLBACK_ERR: AtomicI32 = AtomicI32::new(-1);
static CALLBACK_SYM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

fn orig_add_slot() -> *mut *const c_void {
    ORIG_ADD.as_ptr() as *mut *const c_void
}

extern "C" fn replacement_add(a: c_int, b: c_int) -> c_int {
    let p = ORIG_ADD.load(Ordering::Acquire);
    if p.is_null() {
        return -1;
    }
    // SAFETY: pending 安装完成后 orig 槽写入 trampoline
    let orig: AddFn = unsafe { mem::transmute(p) };
    // SAFETY: ABI 与导出函数一致
    unsafe { orig(a, b) + 1000 }
}

extern "C" fn pending_hooked_cb(
    error: c_int,
    _lib: *const c_char,
    _sym: *const c_char,
    sym_addr: *const c_void,
    _new: *const c_void,
    _orig: *const c_void,
    _arg: *mut c_void,
) {
    CALLBACK_HITS.fetch_add(1, Ordering::SeqCst);
    CALLBACK_ERR.store(error, Ordering::SeqCst);
    CALLBACK_SYM.store(sym_addr as *mut c_void, Ordering::SeqCst);
}

pub fn pending_sym_name_basic() {
    ORIG_ADD.store(ptr::null_mut(), Ordering::SeqCst);
    CALLBACK_HITS.store(0, Ordering::SeqCst);
    CALLBACK_ERR.store(-1, Ordering::SeqCst);
    CALLBACK_SYM.store(ptr::null_mut(), Ordering::SeqCst);

    // SAFETY: 目标 so 此时尚未加载；应进入 pending 队列
    let stub = unsafe {
        hook_sym_name(
            c"libctor_dtor_probe.so",
            c"ctor_dtor_probe_add",
            replacement_add as *const c_void,
            orig_add_slot(),
        )
    }
    .expect("pending_sym_name check failed");
    assert_eq!(get_errno(), Errno::Pending, "pending_sym_name check failed");
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_sym_name check failed"
    );

    // SAFETY: dlopen 触发 ctor pre，pending 任务应在这里自动补装
    let handle = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "pending_sym_name check failed");
    let add_ptr = unsafe { libc::dlsym(handle, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr.is_null(), "pending_sym_name check failed");
    assert!(
        !ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_sym_name check failed"
    );

    // SAFETY: add_ptr 来自 dlsym
    let add_fn: AddFn = unsafe { mem::transmute(add_ptr) };
    // SAFETY: hook 已在 dlopen 期间装好
    let hooked = unsafe { add_fn(3, 4) };
    assert_eq!(hooked, 1007, "pending_sym_name check failed");

    // SAFETY: pending 句柄在完成后应可直接 unhook
    unsafe { unhook(stub).expect("pending_sym_name check failed") };
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_sym_name check failed"
    );
    // SAFETY: 已卸载 hook
    let restored = unsafe { add_fn(3, 4) };
    assert_eq!(restored, 7, "pending_sym_name check failed");
    // SAFETY: handle 来自成功 dlopen
    unsafe { libc::dlclose(handle) };

    // callback 变体：pending 时不应同步回调，待 dlopen 自动安装后回调一次
    let stub2 = unsafe {
        hook_sym_name_callback(
            c"libctor_dtor_probe.so",
            c"ctor_dtor_probe_mul",
            replacement_add as *const c_void,
            orig_add_slot(),
            Some(pending_hooked_cb),
            ptr::null_mut(),
        )
    }
    .expect("pending_sym_name check failed");
    assert_eq!(get_errno(), Errno::Pending, "pending_sym_name check failed");
    assert_eq!(
        CALLBACK_HITS.load(Ordering::SeqCst),
        0,
        "pending_sym_name check failed"
    );

    let handle2 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle2.is_null(), "pending_sym_name check failed");
    let mul_ptr = unsafe { libc::dlsym(handle2, c"ctor_dtor_probe_mul".as_ptr()) };
    assert!(!mul_ptr.is_null(), "pending_sym_name check failed");
    assert_eq!(
        CALLBACK_HITS.load(Ordering::SeqCst),
        1,
        "pending_sym_name check failed"
    );
    assert_eq!(
        CALLBACK_ERR.load(Ordering::SeqCst),
        0,
        "pending_sym_name check failed"
    );
    assert!(
        !CALLBACK_SYM.load(Ordering::SeqCst).is_null(),
        "pending_sym_name check failed"
    );

    let mul_fn: AddFn = unsafe { mem::transmute(mul_ptr) };
    let hooked_mul = unsafe { mul_fn(3, 4) };
    assert_eq!(hooked_mul, 1012, "pending_sym_name check failed");

    unsafe { unhook(stub2).expect("pending_sym_name check failed") };
    let restored_mul = unsafe { mul_fn(3, 4) };
    assert_eq!(restored_mul, 12, "pending_sym_name check failed");
    unsafe { libc::dlclose(handle2) };

    ORIG_ADD.store(ptr::null_mut(), Ordering::SeqCst);
    let wrong_path_stub = unsafe {
        hook_sym_name(
            c"/system/lib64/libctor_dtor_probe.so",
            c"ctor_dtor_probe_add",
            replacement_add as *const c_void,
            orig_add_slot(),
        )
    }
    .expect("pending_sym_name check failed");
    assert_eq!(get_errno(), Errno::Pending, "pending_sym_name check failed");

    let handle3 = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle3.is_null(), "pending_sym_name check failed");
    let add_ptr3 = unsafe { libc::dlsym(handle3, c"ctor_dtor_probe_add".as_ptr()) };
    assert!(!add_ptr3.is_null(), "pending_sym_name check failed");
    assert!(
        ORIG_ADD.load(Ordering::SeqCst).is_null(),
        "pending_sym_name check failed"
    );
    let add_fn3: AddFn = unsafe { mem::transmute(add_ptr3) };
    let plain = unsafe { add_fn3(6, 7) };
    assert_eq!(plain, 13, "pending_sym_name check failed");
    let cancel = unsafe { unhook(wrong_path_stub) };
    assert!(
        matches!(cancel, Err(Errno::UnhookOnUnfinishedTask)),
        "pending_sym_name check failed: {:?}",
        cancel
    );
    unsafe { libc::dlclose(handle3) };

    println!("pending_sym_name_basic: PASS");
}
