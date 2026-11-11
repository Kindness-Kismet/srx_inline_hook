// 共享基础设施：target / replacement 对、静态 STUB 槽、install / clear 工具
// 每个 scenario 模块按需取用，避免 main.rs 巨型

use core::ffi::c_void;
use core::mem;
use std::hint;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use srx_inline_hook::{HookStub, hook_single, prev_func};

pub static HITS_ADD: AtomicUsize = AtomicUsize::new(0);
pub static STUB_ADD: Mutex<Option<HookStub>> = Mutex::new(None);

pub static HITS_MUL: AtomicUsize = AtomicUsize::new(0);
pub static STUB_MUL: Mutex<Option<HookStub>> = Mutex::new(None);

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn target_add(a: i64, b: i64) -> i64 {
    hint::black_box(a).wrapping_add(hint::black_box(b))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn target_mul(a: i64, b: i64) -> i64 {
    hint::black_box(a).wrapping_mul(hint::black_box(b))
}

pub extern "C" fn replacement_add(a: i64, b: i64) -> i64 {
    HITS_ADD.fetch_add(1, Ordering::SeqCst);
    // install → 指令切换 → STUB_ADD 写入存在窗口期；窗口内退化为直加避免 panic
    let Some(stub) = STUB_ADD.lock().ok().and_then(|g| *g) else {
        return a.wrapping_add(b);
    };
    // SAFETY: hook 生效期间 prev_func 返回有效跳板
    let Ok(prev) = (unsafe { prev_func(stub) }) else {
        return a.wrapping_add(b);
    };
    // SAFETY: 跳板 ABI 与原函数一致
    let prev_fn: extern "C" fn(i64, i64) -> i64 = unsafe { mem::transmute(prev) };
    prev_fn(a, b).wrapping_add(1000)
}

pub extern "C" fn replacement_mul(a: i64, b: i64) -> i64 {
    HITS_MUL.fetch_add(1, Ordering::SeqCst);
    let stub = STUB_MUL.lock().expect("lock mul").expect("stub mul");
    // SAFETY: 同 replacement_add
    let prev = unsafe { prev_func(stub).expect("prev mul") };
    // SAFETY: 同 replacement_add
    let prev_fn: extern "C" fn(i64, i64) -> i64 = unsafe { mem::transmute(prev) };
    prev_fn(a, b).wrapping_add(2)
}

pub fn install(
    cell: &Mutex<Option<HookStub>>,
    target: unsafe extern "C" fn(i64, i64) -> i64,
    rep: extern "C" fn(i64, i64) -> i64,
) -> HookStub {
    // SAFETY: target 与 rep 为本进程可执行地址
    let stub =
        unsafe { hook_single(target as *mut c_void, rep as *const c_void).expect("hook_single") };
    *cell.lock().expect("lock") = Some(stub);
    stub
}

pub fn clear(cell: &Mutex<Option<HookStub>>) {
    *cell.lock().expect("lock") = None;
}
