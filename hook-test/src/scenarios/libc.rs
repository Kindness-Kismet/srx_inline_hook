// 真机 libc hook 场景：bionic strlen；触发 arm64 ADRP / x86_64 RIP 相对 rewriter 路径

use core::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use srx_inline_hook::{HookStub, hook_single, prev_func, unhook};

static STUB_STRLEN: Mutex<Option<HookStub>> = Mutex::new(None);
static HITS_STRLEN: AtomicUsize = AtomicUsize::new(0);
const STRLEN_BONUS: usize = 1000;

type StrlenFn = unsafe extern "C" fn(*const core::ffi::c_char) -> usize;

extern "C" fn replacement_strlen(s: *const core::ffi::c_char) -> usize {
    HITS_STRLEN.fetch_add(1, Ordering::SeqCst);
    let stub = STUB_STRLEN
        .lock()
        .expect("lock strlen")
        .expect("stub strlen");
    // SAFETY: hook 生效期间 prev_func 返回有效跳板
    let prev = unsafe { prev_func(stub).expect("prev strlen") };
    // SAFETY: 跳板 ABI 与 strlen 一致
    let prev_fn: StrlenFn = unsafe { core::mem::transmute(prev) };
    // SAFETY: s 由调用方保证 NUL 终止
    let real = unsafe { prev_fn(s) };
    real + STRLEN_BONUS
}

pub fn hook_libc_strlen() {
    let libc_name = c"libc.so";
    // SAFETY: libc_name 为 'static CStr；dlopen 仅返回 handle
    let h = unsafe { libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOW) };
    if h.is_null() {
        println!("hook_libc_strlen: skipped");
        return;
    }
    let sym = c"strlen";
    // SAFETY: h 来自 dlopen；sym 为 'static CStr
    let strlen_ptr = unsafe { libc::dlsym(h, sym.as_ptr()) };
    if strlen_ptr.is_null() {
        println!("hook_libc_strlen: skipped");
        return;
    }

    // 诊断：打印 strlen 前 24 字节，便于定位未覆盖指令家族
    let mut buf = [0u8; 24];
    // SAFETY: strlen_ptr 指向可读可执行页
    unsafe {
        core::ptr::copy_nonoverlapping(strlen_ptr as *const u8, buf.as_mut_ptr(), 24);
    }
    let mut hex = String::new();
    for w in buf.chunks_exact(4) {
        let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        hex.push_str(&format!("{:08x} ", v));
    }
    println!(
        "hook_libc_strlen: strlen@{:p} prologue = {}",
        strlen_ptr,
        hex.trim()
    );

    let probe = c"hook-me!";
    // SAFETY: probe 为 'static NUL 终止字符串
    let before = unsafe {
        let f: StrlenFn = core::mem::transmute(strlen_ptr);
        f(probe.as_ptr())
    };
    assert_eq!(before, 8);

    HITS_STRLEN.store(0, Ordering::SeqCst);
    // SAFETY: strlen_ptr 指向 libc 可执行代码
    let result = unsafe { hook_single(strlen_ptr, replacement_strlen as *const c_void) };
    let stub = match result {
        Ok(s) => s,
        Err(e) => {
            println!("hook_libc_strlen: skipped: {:?}", e);
            return;
        }
    };
    *STUB_STRLEN.lock().expect("lock strlen") = Some(stub);

    // SAFETY: 同 before
    let hooked = unsafe {
        let f: StrlenFn = core::mem::transmute(strlen_ptr);
        f(probe.as_ptr())
    };
    assert_eq!(hooked, 8 + STRLEN_BONUS);
    assert_eq!(HITS_STRLEN.load(Ordering::SeqCst), 1);

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook strlen") };
    *STUB_STRLEN.lock().expect("lock strlen") = None;

    // SAFETY: 同 before
    let restored = unsafe {
        let f: StrlenFn = core::mem::transmute(strlen_ptr);
        f(probe.as_ptr())
    };
    assert_eq!(restored, 8);
    println!("hook_libc_strlen: PASS");
}
