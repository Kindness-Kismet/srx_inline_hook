// hook_sym_name 场景：按 so + 符号名安装 hook
// 调用路径走 dlsym 返回地址，避开 LLVM 对 libc::strlen 的内联

use core::ffi::{c_char, c_void};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};

use srx_inline_hook::{hook_sym_name, hook_sym_name_callback, unhook};

type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;

static ORIG_STRLEN: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

fn orig_strlen_slot() -> *mut *const c_void {
    ORIG_STRLEN.as_ptr() as *mut *const c_void
}

extern "C" fn replacement_strlen_by_name(s: *const c_char) -> usize {
    let p = ORIG_STRLEN.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    // SAFETY: hook 激活后 orig 槽由库写入，unhook 后清零
    let orig: StrlenFn = unsafe { mem::transmute(p) };
    // SAFETY: 由调用方保证 NUL 终止
    let real = unsafe { orig(s) };
    real + 2000
}

pub fn hook_sym_name_basic() {
    // 通过 dlsym 取 strlen 实际入口，避免 LLVM libcall 识别绕过 hook
    // SAFETY: libc.so 为 'static；dlopen 仅返回句柄
    let h = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    if h.is_null() {
        println!("hook_sym_name_basic: SKIP (dlopen libc.so)");
        return;
    }
    // SAFETY: h 来自 dlopen
    let strlen_addr = unsafe { libc::dlsym(h, c"strlen".as_ptr()) };
    if strlen_addr.is_null() {
        println!("hook_sym_name_basic: SKIP (dlsym strlen)");
        return;
    }
    // SAFETY: strlen_addr 来自 dlsym
    let strlen_fn: StrlenFn = unsafe { mem::transmute(strlen_addr) };

    let probe = c"sym-name!";
    // SAFETY: probe 为 'static
    let plain = unsafe { strlen_fn(probe.as_ptr()) };
    assert_eq!(plain, 9);

    // SAFETY: 所有入参均为 'static 或库管理
    let result = unsafe {
        hook_sym_name(
            c"libc.so",
            c"strlen",
            replacement_strlen_by_name as *const c_void,
            orig_strlen_slot(),
        )
    };
    let stub = match result {
        Ok(s) => s,
        Err(e) => {
            // bionic strlen 某些架构上含未覆盖指令 → SKIP
            println!("hook_sym_name_basic: SKIP ({:?})", e);
            return;
        }
    };

    assert!(!ORIG_STRLEN.load(Ordering::SeqCst).is_null());

    // SAFETY: hook 已装
    let hooked = unsafe { strlen_fn(probe.as_ptr()) };
    assert_eq!(hooked, 9 + 2000, "sym_name check failed");

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    assert!(
        ORIG_STRLEN.load(Ordering::SeqCst).is_null(),
        "sym_name check failed"
    );

    // SAFETY: 已卸载
    let restored = unsafe { strlen_fn(probe.as_ptr()) };
    assert_eq!(restored, 9);
    println!("hook_sym_name_basic: PASS");
}

// callback 变体：hook 成功/失败都同步触发一次 cb，验证 error 与 sym_addr 传参
static CB_HIT: AtomicU32 = AtomicU32::new(0);
static CB_ERROR: AtomicI32 = AtomicI32::new(-1);
static CB_SYM_ADDR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

extern "C" fn test_hooked_cb(
    error: i32,
    _lib: *const c_char,
    _sym: *const c_char,
    sym_addr: *const c_void,
    _new: *const c_void,
    _orig: *const c_void,
    _arg: *mut c_void,
) {
    CB_HIT.fetch_add(1, Ordering::SeqCst);
    CB_ERROR.store(error, Ordering::SeqCst);
    CB_SYM_ADDR.store(sym_addr as *mut c_void, Ordering::SeqCst);
}

pub fn hook_sym_name_callback_basic() {
    // 失败路径：不存在的 sym，cb 应收到 error != 0
    CB_HIT.store(0, Ordering::SeqCst);
    CB_ERROR.store(0, Ordering::SeqCst);
    CB_SYM_ADDR.store(ptr::null_mut(), Ordering::SeqCst);

    // SAFETY: dummy replacement 非 null 以过前置校验；失败在 dlsym 阶段
    let r = unsafe {
        hook_sym_name_callback(
            c"libc.so",
            c"srx_absent_symbol_xyz",
            hook_sym_name_callback_basic as *const c_void,
            ptr::null_mut(),
            Some(test_hooked_cb),
            ptr::null_mut(),
        )
    };
    assert!(r.is_err(), "sym_name check failed");
    assert_eq!(CB_HIT.load(Ordering::SeqCst), 1, "sym_name check failed");
    assert_ne!(CB_ERROR.load(Ordering::SeqCst), 0, "sym_name check failed");

    // 成功路径：hook libc.so strlen，cb 应收到 error == 0 + sym_addr 非空
    // SAFETY: libc.so 可加载
    let h = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    if h.is_null() {
        println!("hook_sym_name_callback_basic: SKIP (dlopen)");
        return;
    }

    CB_HIT.store(0, Ordering::SeqCst);
    CB_ERROR.store(-1, Ordering::SeqCst);
    CB_SYM_ADDR.store(ptr::null_mut(), Ordering::SeqCst);

    // SAFETY: 所有入参 'static；replacement 为本 scenario 内函数
    let r = unsafe {
        hook_sym_name_callback(
            c"libc.so",
            c"strlen",
            replacement_strlen_by_name as *const c_void,
            orig_strlen_slot(),
            Some(test_hooked_cb),
            ptr::null_mut(),
        )
    };
    let Ok(stub) = r else {
        println!("hook_sym_name_callback_basic: SKIP (hook strlen {:?})", r);
        return;
    };

    assert_eq!(CB_HIT.load(Ordering::SeqCst), 1, "sym_name check failed");
    assert_eq!(CB_ERROR.load(Ordering::SeqCst), 0, "sym_name check failed");
    assert!(
        !CB_SYM_ADDR.load(Ordering::SeqCst).is_null(),
        "sym_name check failed"
    );

    CB_HIT.store(0, Ordering::SeqCst);
    CB_ERROR.store(-1, Ordering::SeqCst);
    CB_SYM_ADDR.store(ptr::null_mut(), Ordering::SeqCst);
    let dup = unsafe {
        hook_sym_name_callback(
            c"libc.so",
            c"strlen",
            replacement_strlen_by_name as *const c_void,
            orig_strlen_slot(),
            Some(test_hooked_cb),
            ptr::null_mut(),
        )
    };
    assert!(dup.is_err(), "sym_name check failed");
    assert_eq!(CB_HIT.load(Ordering::SeqCst), 1, "sym_name check failed");
    assert_ne!(CB_ERROR.load(Ordering::SeqCst), 0, "sym_name check failed");
    assert!(
        !CB_SYM_ADDR.load(Ordering::SeqCst).is_null(),
        "sym_name check failed"
    );

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    println!("hook_sym_name_callback_basic: PASS");
}
