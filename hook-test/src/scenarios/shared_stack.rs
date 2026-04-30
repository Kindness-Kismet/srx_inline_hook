// SHARED stack API：递归默认抑制；allow_reentrant 后允许进入下一层

use core::ffi::c_void;
use core::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use srx_inline_hook::{HookStub, hook_sym_addr_2, prev_func, unhook};

unsafe extern "C" {
    fn srx_inline_hook_pop_stack(return_address: *mut c_void);
    fn srx_inline_hook_allow_reentrant(return_address: *mut c_void);
    fn srx_inline_hook_disallow_reentrant(return_address: *mut c_void);
    fn srx_inline_hook_get_return_address() -> *mut c_void;
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn stack_target(a: i64, b: i64) -> i64 {
    std::hint::black_box(a).wrapping_add(std::hint::black_box(b))
}

type AddFn = extern "C" fn(i64, i64) -> i64;
static STUB_STACK: Mutex<Option<HookStub>> = Mutex::new(None);
static STACK_DEPTH: AtomicI32 = AtomicI32::new(0);
static EARLY_RETURN_ONCE: AtomicBool = AtomicBool::new(false);
static SEEN_RETURN_ADDRESS: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl shared_stack_return_probe",
    ".type shared_stack_return_probe, @function",
    "shared_stack_return_probe:",
    "    sub rsp, 8",
    "    call stack_target",
    "shared_stack_return_probe_after_call:",
    "    add rsp, 8",
    "    ret",
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn shared_stack_return_probe(a: i64, b: i64) -> i64;
    static shared_stack_return_probe_after_call: u8;
}

extern "C" fn stack_proxy(a: i64, b: i64) -> i64 {
    let depth = STACK_DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    let return_address = unsafe { srx_inline_hook_get_return_address() };
    assert!(!return_address.is_null(), "shared_stack check failed");

    if depth == 1 {
        SEEN_RETURN_ADDRESS.store(return_address as usize, Ordering::SeqCst);
    }

    let stub = STUB_STACK.lock().expect("lock stack").expect("stub stack");
    let prev = unsafe { prev_func(stub).expect("prev stack") };
    let prev_fn: AddFn = unsafe { core::mem::transmute(prev) };
    let target_fn: AddFn = unsafe { core::mem::transmute(stack_target as *const c_void) };

    if depth == 1 && EARLY_RETURN_ONCE.swap(false, Ordering::SeqCst) {
        unsafe { srx_inline_hook_pop_stack(return_address) };
        STACK_DEPTH.fetch_sub(1, Ordering::SeqCst);
        return -77;
    }

    let result = if depth == 1 {
        let blocked = target_fn(a, b);
        assert_eq!(blocked, a + b, "shared_stack check failed");

        let nested_before = target_fn(a, b);
        assert_eq!(nested_before, a + b, "shared_stack check failed");

        unsafe { srx_inline_hook_allow_reentrant(return_address) };
        let nested = target_fn(a, b);
        assert_eq!(nested, a + b + 30, "shared_stack check failed");
        unsafe { srx_inline_hook_disallow_reentrant(return_address) };
        let blocked_again = target_fn(a, b);
        assert_eq!(blocked_again, a + b, "shared_stack check failed");
        nested
    } else {
        prev_fn(a, b)
    };

    unsafe { srx_inline_hook_pop_stack(return_address) };
    STACK_DEPTH.fetch_sub(1, Ordering::SeqCst);
    result + 30
}

pub fn shared_stack_api_basic() {
    EARLY_RETURN_ONCE.store(false, Ordering::SeqCst);
    SEEN_RETURN_ADDRESS.store(0, Ordering::SeqCst);
    let stub = unsafe {
        hook_sym_addr_2(
            stack_target as *mut c_void,
            stack_proxy as *const c_void,
            ptr::null_mut(),
            1,
        )
    }
    .expect("shared_stack check failed");
    *STUB_STACK.lock().expect("lock stack") = Some(stub);

    let target: AddFn = unsafe { core::mem::transmute(stack_target as *const c_void) };
    #[cfg(target_arch = "x86_64")]
    let probe: AddFn = unsafe { core::mem::transmute(shared_stack_return_probe as *const c_void) };
    #[cfg(target_arch = "x86_64")]
    let probe_after_call = core::ptr::addr_of!(shared_stack_return_probe_after_call) as usize;
    #[cfg(target_arch = "x86_64")]
    assert_eq!(probe(3, 4), 67, "shared_stack check failed");
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        SEEN_RETURN_ADDRESS.load(Ordering::SeqCst),
        probe_after_call,
        "shared_stack check failed"
    );
    assert_eq!(target(3, 4), 67, "shared_stack check failed");

    EARLY_RETURN_ONCE.store(true, Ordering::SeqCst);
    assert_eq!(target(9, 1), -77, "shared_stack check failed");
    assert_eq!(target(3, 4), 67, "shared_stack check failed");

    unsafe { unhook(stub).expect("unhook shared stack") };
    *STUB_STACK.lock().expect("lock stack") = None;
    assert_eq!(target(3, 4), 7, "shared_stack check failed");

    println!("shared_stack_api_basic: PASS");
}
