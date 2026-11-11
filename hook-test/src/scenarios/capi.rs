// C FFI 契约检查：extern 声明调用本 crate 导出的符号，验证可链接
// 按 API 域拆分场景，覆盖状态、hook、intercept、记录与头文件契约

use core::arch::global_asm;
use core::ffi::{c_char, c_int, c_void};
use core::mem;
use core::ptr;
use core::slice;
use core::str;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};
use std::hint;
use std::sync::Mutex;

type HookedFn = extern "C" fn(
    error: c_int,
    lib_name: *const c_char,
    sym_name: *const c_char,
    sym_addr: *const c_void,
    new_addr: *const c_void,
    orig_addr: *const c_void,
    arg: *mut c_void,
);

unsafe extern "C" {
    fn srx_inline_hook_get_version() -> *const c_char;
    fn srx_inline_hook_init(mode: c_int, debuggable: bool) -> c_int;
    fn srx_inline_hook_get_init_errno() -> c_int;
    fn srx_inline_hook_get_mode() -> c_int;
    fn srx_inline_hook_get_debuggable() -> bool;
    fn srx_inline_hook_set_debuggable(debuggable: bool);
    fn srx_inline_hook_get_disable() -> bool;
    fn srx_inline_hook_set_disable(disable: bool);
    fn srx_inline_hook_get_errno() -> c_int;
    fn srx_inline_hook_to_errmsg(error_number: c_int) -> *const c_char;
    fn srx_inline_hook_hook_func_addr(
        func_addr: *mut c_void,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_hook_sym_addr(
        sym_addr: *mut c_void,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_hook_sym_name(
        lib_name: *const c_char,
        sym_name: *const c_char,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_hook_sym_name_callback(
        lib_name: *const c_char,
        sym_name: *const c_char,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
        hooked: Option<HookedFn>,
        hooked_arg: *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_hook_sym_name_callback_2(
        lib_name: *const c_char,
        sym_name: *const c_char,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
        flags: u32,
        hooked: Option<HookedFn>,
        hooked_arg: *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_unhook(stub: *mut c_void) -> c_int;
    fn srx_inline_hook_get_prev_func(func: *mut c_void) -> *mut c_void;
    fn srx_inline_hook_set_recordable(recordable: bool);
    fn srx_inline_hook_get_recordable() -> bool;
    fn srx_inline_hook_dump_records(fd: c_int, item_flags: u32);
    fn srx_inline_hook_get_records(item_flags: u32) -> *mut c_char;
    fn srx_inline_hook_dlopen(lib_name: *const c_char) -> *mut c_void;
    fn srx_inline_hook_dlclose(handle: *mut c_void);
    fn srx_inline_hook_dlsym(handle: *mut c_void, sym_name: *const c_char) -> *mut c_void;
    fn srx_inline_hook_dlsym_dynsym(handle: *mut c_void, sym_name: *const c_char) -> *mut c_void;
    fn srx_inline_hook_dlsym_symtab(handle: *mut c_void, sym_name: *const c_char) -> *mut c_void;
    fn srx_inline_hook_hook_sym_name_2(
        lib_name: *const c_char,
        sym_name: *const c_char,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
        flags: u32,
    ) -> *mut c_void;
    fn srx_inline_hook_intercept_instr_addr(
        instr_addr: *mut c_void,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
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
        lib_name: *const c_char,
        sym_name: *const c_char,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
    ) -> *mut c_void;
    fn srx_inline_hook_intercept_sym_name_callback(
        lib_name: *const c_char,
        sym_name: *const c_char,
        pre: *mut c_void,
        data: *mut c_void,
        flags: u32,
        intercepted: *mut c_void,
        intercepted_arg: *mut c_void,
    ) -> *mut c_void;
    fn srx_inline_hook_unintercept(stub: *mut c_void) -> c_int;
    fn srx_inline_hook_register_dl_init_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> c_int;
    fn srx_inline_hook_unregister_dl_init_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> c_int;
    fn srx_inline_hook_register_dl_fini_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> c_int;
    fn srx_inline_hook_unregister_dl_fini_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> c_int;
    fn srx_inline_hook_pop_stack(return_address: *mut c_void);
    fn srx_inline_hook_allow_reentrant(return_address: *mut c_void);
    fn srx_inline_hook_disallow_reentrant(return_address: *mut c_void);
    fn srx_inline_hook_hook_func_addr_2(
        func_addr: *mut c_void,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
    fn srx_inline_hook_hook_sym_addr_2(
        sym_addr: *mut c_void,
        new_addr: *mut c_void,
        orig_addr: *mut *mut c_void,
        flags: u32,
        ...
    ) -> *mut c_void;
}

const SRX_INLINE_HOOK_HEADER_TEXT: &str = include_str!("../../../include/srx_inline_hook.h");

type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;
type ProbeFn = unsafe extern "C" fn(c_int, c_int) -> c_int;

#[inline(never)]
fn copy_c_string(ptr: *const c_char) -> String {
    let mut len = 0usize;
    loop {
        let ch = unsafe { ptr::read_volatile(ptr.add(len)) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    let bytes = unsafe { slice::from_raw_parts(ptr.cast::<u8>(), len) };
    str::from_utf8(bytes)
        .expect("callback string utf8")
        .to_owned()
}

static mut CAPI_STUB: *mut c_void = ptr::null_mut();
static CAPI_INTERCEPT_CB_HITS: AtomicI32 = AtomicI32::new(0);
// 记录 capi_hooked_cb 收到的 orig_addr 值，供上层断言与用户传入的 slot 地址一致
static CAPI_CB_ORIG_ADDR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_CB_SYM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_CB_NEW_ADDR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_CB_ARG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_CB_LIB_NAME_TEXT: Mutex<Option<String>> = Mutex::new(None);
static CAPI_CB_SYM_NAME_TEXT: Mutex<Option<String>> = Mutex::new(None);
static CAPI_INTERCEPT_CB_ARG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_INTERCEPT_CB_LIB_NAME_TEXT: Mutex<Option<String>> = Mutex::new(None);
static CAPI_INTERCEPT_CB_SYM_NAME_TEXT: Mutex<Option<String>> = Mutex::new(None);
static CAPI_PENDING_ORIG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_PENDING_CB_HITS: AtomicU32 = AtomicU32::new(0);
static CAPI_PENDING_CB_ERR: AtomicI32 = AtomicI32::new(-1);
static CAPI_PENDING_CB_SYM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_PENDING_CB_NEW_ADDR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_PENDING_CB_ARG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_PENDING_CB_ORIG_ADDR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CAPI_PENDING_CB_LIB_NAME_TEXT: Mutex<Option<String>> = Mutex::new(None);
static CAPI_PENDING_CB_SYM_NAME_TEXT: Mutex<Option<String>> = Mutex::new(None);

extern "C" fn replacement_capi_strlen(s: *const c_char) -> usize {
    let prev = unsafe { srx_inline_hook_get_prev_func(replacement_capi_strlen as *mut c_void) };
    // SAFETY: 跳板 ABI 与 strlen 一致
    let prev_fn: StrlenFn = unsafe { mem::transmute(prev) };
    // SAFETY: s 由调用方保证 NUL 终止
    unsafe { prev_fn(s) + 500 }
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn capi_intercept_target(a: i64, b: i64) -> i64 {
    hint::black_box(a).wrapping_add(hint::black_box(b))
}

extern "C" fn capi_intercept_pre(_ctx: *mut c_void, _data: *mut c_void) {}

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".globl capi_overlap_a",
    ".type capi_overlap_a, @function",
    "capi_overlap_a:",
    "    mov eax, 11",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    ret",
    ".globl capi_overlap_b",
    ".type capi_overlap_b, @function",
    "capi_overlap_b:",
    "    mov eax, 33",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    nop",
    "    ret",
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    ".globl capi_overlap_a",
    ".type capi_overlap_a, %function",
    "capi_overlap_a:",
    "    mov x0, #11",
    "    mov x1, #22",
    "    ret",
    ".globl capi_overlap_b",
    ".type capi_overlap_b, %function",
    "capi_overlap_b:",
    "    mov x0, #33",
    "    mov x1, #44",
    "    ret",
    "    nop",
    "    nop",
    "    nop",
);

unsafe extern "C" {
    fn capi_overlap_a() -> i64;
    fn capi_overlap_b() -> i64;
}

extern "C" fn capi_overlap_replacement() -> i64 {
    0
}

extern "C" fn capi_hook_addr_replacement(a: i64, b: i64) -> i64 {
    hint::black_box(a)
        .wrapping_add(hint::black_box(b))
        .wrapping_add(700)
}

extern "C" fn capi_hook_sym_replacement(a: i64, b: i64) -> i64 {
    hint::black_box(a)
        .wrapping_add(hint::black_box(b))
        .wrapping_add(900)
}

extern "C" fn capi_hooked_cb(
    error: c_int,
    lib_name: *const c_char,
    sym_name: *const c_char,
    sym_addr: *const c_void,
    new_addr: *const c_void,
    orig_addr: *const c_void,
    arg: *mut c_void,
) {
    // orig_addr 为用户传入的 void** 槽位地址本身
    CAPI_CB_ORIG_ADDR.store(orig_addr as *mut c_void, Ordering::Release);
    CAPI_CB_SYM.store(sym_addr as *mut c_void, Ordering::Release);
    CAPI_CB_NEW_ADDR.store(new_addr as *mut c_void, Ordering::Release);
    CAPI_CB_ARG.store(arg, Ordering::Release);
    *CAPI_CB_LIB_NAME_TEXT.lock().expect("lock hook cb lib") = if lib_name.is_null() {
        None
    } else {
        Some(copy_c_string(lib_name))
    };
    *CAPI_CB_SYM_NAME_TEXT.lock().expect("lock hook cb sym") = if sym_name.is_null() {
        None
    } else {
        Some(copy_c_string(sym_name))
    };
    // arg 指向 i32 计数器；记录 error 供上层断言
    if !arg.is_null() {
        // SAFETY: arg 由调用方持有 'static 存活期
        unsafe { *(arg as *mut c_int) = error };
    }
}

extern "C" fn capi_pending_replacement(a: c_int, b: c_int) -> c_int {
    let p = CAPI_PENDING_ORIG.load(Ordering::Acquire);
    if p.is_null() {
        return -1;
    }
    let orig: ProbeFn = unsafe { mem::transmute(p) };
    unsafe { orig(a, b) + 1000 }
}

extern "C" fn capi_pending_hooked_cb(
    error: c_int,
    lib_name: *const c_char,
    sym_name: *const c_char,
    sym_addr: *const c_void,
    new_addr: *const c_void,
    orig_addr: *const c_void,
    arg: *mut c_void,
) {
    CAPI_PENDING_CB_HITS.fetch_add(1, Ordering::SeqCst);
    CAPI_PENDING_CB_ERR.store(error, Ordering::SeqCst);
    CAPI_PENDING_CB_SYM.store(sym_addr as *mut c_void, Ordering::SeqCst);
    CAPI_PENDING_CB_NEW_ADDR.store(new_addr as *mut c_void, Ordering::SeqCst);
    CAPI_PENDING_CB_ARG.store(arg, Ordering::Release);
    CAPI_PENDING_CB_ORIG_ADDR.store(orig_addr as *mut c_void, Ordering::Release);
    *CAPI_PENDING_CB_LIB_NAME_TEXT
        .lock()
        .expect("lock pending cb lib") = if lib_name.is_null() {
        None
    } else {
        Some(copy_c_string(lib_name))
    };
    *CAPI_PENDING_CB_SYM_NAME_TEXT
        .lock()
        .expect("lock pending cb sym") = if sym_name.is_null() {
        None
    } else {
        Some(copy_c_string(sym_name))
    };
}

extern "C" fn capi_intercepted_cb(
    _error: c_int,
    lib_name: *const c_char,
    sym_name: *const c_char,
    _sym_addr: *const c_void,
    _pre: *mut c_void,
    _data: *mut c_void,
    arg: *mut c_void,
) {
    CAPI_INTERCEPT_CB_ARG.store(arg, Ordering::Release);
    *CAPI_INTERCEPT_CB_LIB_NAME_TEXT
        .lock()
        .expect("lock intercept cb lib") = if lib_name.is_null() {
        None
    } else {
        Some(copy_c_string(lib_name))
    };
    *CAPI_INTERCEPT_CB_SYM_NAME_TEXT
        .lock()
        .expect("lock intercept cb sym") = if sym_name.is_null() {
        None
    } else {
        Some(copy_c_string(sym_name))
    };
    CAPI_INTERCEPT_CB_HITS.fetch_add(1, Ordering::SeqCst);
}

#[path = "capi/callback_contract.rs"]
mod callback_contract;
#[path = "capi/hook_addr_flags.rs"]
mod hook_addr_flags;
#[path = "capi/hook_name.rs"]
mod hook_name;
#[path = "capi/intercept_addr.rs"]
mod intercept_addr;
#[path = "capi/intercept_name.rs"]
mod intercept_name;
#[path = "capi/lookup_flags.rs"]
mod lookup_flags;
#[path = "capi/pending.rs"]
mod pending;
#[path = "capi/state.rs"]
mod state;

pub fn capi_state() {
    state::run();
}

pub fn capi_hook_name() {
    hook_name::run();
}

pub fn capi_pending() {
    pending::run();
}

pub fn capi_lookup_flags() {
    lookup_flags::run();
}

pub fn capi_intercept_addr() {
    intercept_addr::run();
}

pub fn capi_intercept_name() {
    intercept_name::run();
}

pub fn capi_callback_contract() {
    callback_contract::run();
}

pub fn capi_hook_addr_flags() {
    hook_addr_flags::run();
}
