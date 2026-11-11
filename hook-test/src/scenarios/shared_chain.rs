// SHARED 最小链：同一 target 两个代理共享 trampoline，prev_func 应返回下一环或原函数

use core::ffi::c_void;
use core::mem;
use core::ptr;
use std::hint;
use std::sync::Mutex;

use srx_inline_hook::{HookStub, hook_sym_addr_2, prev_func, unhook};

unsafe extern "C" {
    fn srx_inline_hook_pop_stack(return_address: *mut c_void);
    fn srx_inline_hook_get_return_address() -> *mut c_void;
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn shared_target(a: i64, b: i64) -> i64 {
    hint::black_box(a).wrapping_add(hint::black_box(b))
}

type AddFn = extern "C" fn(i64, i64) -> i64;

fn shared_target_fn() -> AddFn {
    // SAFETY: shared_target 为本进程内稳定函数入口
    unsafe { mem::transmute(shared_target as *const c_void) }
}

static STUB_A: Mutex<Option<HookStub>> = Mutex::new(None);
static STUB_B: Mutex<Option<HookStub>> = Mutex::new(None);

extern "C" fn shared_a(a: i64, b: i64) -> i64 {
    let stub = STUB_A.lock().expect("lock a").expect("stub a");
    let prev = unsafe { prev_func(stub).expect("prev a") };
    let f: AddFn = unsafe { mem::transmute(prev) };
    let ra = unsafe { srx_inline_hook_get_return_address() };
    assert!(!ra.is_null(), "shared_chain check failed");
    let result = f(a, b) + 10;
    unsafe { srx_inline_hook_pop_stack(ra) };
    result
}

extern "C" fn shared_b(a: i64, b: i64) -> i64 {
    let stub = STUB_B.lock().expect("lock b").expect("stub b");
    let prev = unsafe { prev_func(stub).expect("prev b") };
    let f: AddFn = unsafe { mem::transmute(prev) };
    let ra = unsafe { srx_inline_hook_get_return_address() };
    assert!(!ra.is_null(), "shared_chain check failed");
    let result = f(a, b) * 2;
    unsafe { srx_inline_hook_pop_stack(ra) };
    result
}

pub fn shared_chain_basic() {
    // SAFETY: target/replacement 为本进程代码地址
    let stub_a = unsafe {
        hook_sym_addr_2(
            shared_target as *mut c_void,
            shared_a as *const c_void,
            ptr::null_mut(),
            1,
        )
    }
    .expect("shared_chain check failed");
    *STUB_A.lock().expect("lock a") = Some(stub_a);

    let mut orig_b: *const c_void = ptr::null();
    let stub_b = unsafe {
        hook_sym_addr_2(
            shared_target as *mut c_void,
            shared_b as *const c_void,
            &mut orig_b as *mut *const c_void,
            1,
        )
    }
    .expect("shared_chain check failed");
    *STUB_B.lock().expect("lock b") = Some(stub_b);
    assert!(!orig_b.is_null(), "shared_chain check failed");

    let target = shared_target_fn();
    assert_eq!(target(3, 4), 24, "shared_chain check failed");

    unsafe { unhook(stub_a).expect("unhook shared a") };
    *STUB_A.lock().expect("lock a") = None;
    assert_eq!(target(3, 4), 14, "shared_chain check failed");

    unsafe { unhook(stub_b).expect("unhook shared b") };
    *STUB_B.lock().expect("lock b") = None;
    assert_eq!(target(3, 4), 7, "shared_chain check failed");

    println!("shared_chain_basic: PASS");
}
