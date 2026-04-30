// SIGSEGV / SIGBUS / SIGILL 守卫：sigaction 注册 + 按 tid 的 sigsetjmp 槽 + prev_action 转发
// 未命中当前 tid 时转交上一个 handler

use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::errno::Errno;
use crate::util::encode_signal_exit;

// 每信号并发守卫上限，固定数组便于在 signal handler 中无锁扫描
const MAX_PROTECTED_THREADS: usize = 256;
// sigjmp_buf 兼容上限：aarch64 bionic ~272B / x86_64 bionic ~160B
const SIGJMP_BUF_WORDS: usize = 64;

#[repr(C, align(16))]
pub struct SigJmpBuf([u64; SIGJMP_BUF_WORDS]);

impl SigJmpBuf {
    pub const fn zeroed() -> Self {
        Self([0; SIGJMP_BUF_WORDS])
    }
}

unsafe extern "C" {
    fn sigsetjmp(env: *mut SigJmpBuf, savesigs: c_int) -> c_int;
    fn siglongjmp(env: *mut SigJmpBuf, val: c_int) -> !;
}

struct Slots {
    tids: [AtomicI32; MAX_PROTECTED_THREADS],
    jbufs: [AtomicPtr<SigJmpBuf>; MAX_PROTECTED_THREADS],
}

impl Slots {
    const fn new() -> Self {
        Self {
            tids: [const { AtomicI32::new(0) }; MAX_PROTECTED_THREADS],
            jbufs: [const { AtomicPtr::new(ptr::null_mut()) }; MAX_PROTECTED_THREADS],
        }
    }
}

static SEGV_SLOTS: Slots = Slots::new();
static BUS_SLOTS: Slots = Slots::new();
static ILL_SLOTS: Slots = Slots::new();
static SEGV_PREV: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());
static BUS_PREV: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());
static ILL_PREV: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());
static INSTALLED: AtomicBool = AtomicBool::new(false);
static INIT_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub fn init() -> Result<(), Errno> {
    let _g = INIT_LOCK.lock().map_err(|_| Errno::InitSigsegv)?;
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }
    install(libc::SIGSEGV, &SEGV_PREV)?;
    install(libc::SIGBUS, &BUS_PREV)?;
    install(libc::SIGILL, &ILL_PREV)?;
    INSTALLED.store(true, Ordering::Release);
    Ok(())
}

fn install(signum: c_int, prev_slot: &AtomicPtr<libc::sigaction>) -> Result<(), Errno> {
    // prev_action 堆分配并登记进全局 AtomicPtr，终身存活无需回收
    // SAFETY: 零值 sigaction 与 sigfillset 组合符合 POSIX 规约
    let prev = Box::leak(Box::new(unsafe { core::mem::zeroed::<libc::sigaction>() }));
    // SAFETY: act 以零值起步，下方仅填充 sa_mask / sa_flags / sa_sigaction
    let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
    // SAFETY: sigfillset 仅写入 act.sa_mask
    unsafe { libc::sigfillset(&mut act.sa_mask) };
    // SA_EXPOSE_TAGBITS = 0x800：MTE 启用时保留 si_addr 的 tag 位，libc crate 未暴露常量
    const SA_EXPOSE_TAGBITS: c_int = 0x0000_0800;
    act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESTART | SA_EXPOSE_TAGBITS;
    act.sa_sigaction = handler as *const c_void as libc::sighandler_t;
    // SAFETY: act 字段完整，prev 为堆上 sigaction 可写目标
    let rc = unsafe { libc::sigaction(signum, &act, prev) };
    if rc != 0 {
        return Err(match signum {
            libc::SIGBUS => Errno::InitSigbus,
            libc::SIGILL => Errno::InitSigill,
            _ => Errno::InitSigsegv,
        });
    }
    prev_slot.store(prev as *mut _, Ordering::Release);
    Ok(())
}

fn slots_for(signum: c_int) -> Option<&'static Slots> {
    match signum {
        libc::SIGSEGV => Some(&SEGV_SLOTS),
        libc::SIGBUS => Some(&BUS_SLOTS),
        libc::SIGILL => Some(&ILL_SLOTS),
        _ => None,
    }
}

fn prev_for(signum: c_int) -> Option<&'static AtomicPtr<libc::sigaction>> {
    match signum {
        libc::SIGSEGV => Some(&SEGV_PREV),
        libc::SIGBUS => Some(&BUS_PREV),
        libc::SIGILL => Some(&ILL_PREV),
        _ => None,
    }
}

#[inline]
fn current_tid() -> i32 {
    // SAFETY: SYS_gettid 纯查询，无副作用
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

unsafe extern "C" fn handler(signum: c_int, info: *mut libc::siginfo_t, ctx: *mut c_void) {
    if let Some(slots) = slots_for(signum) {
        let tid = current_tid();
        for i in 0..MAX_PROTECTED_THREADS {
            if slots.tids[i].load(Ordering::Acquire) == tid {
                let code = if info.is_null() {
                    0
                } else {
                    // SAFETY: info 非空时由 kernel 保证有效
                    unsafe { (*info).si_code }
                };
                let ret = encode_signal_exit(signum, code);
                let jbuf = slots.jbufs[i].load(Ordering::Relaxed);
                if !jbuf.is_null() {
                    // SAFETY: jbuf 由 guard 的 sigsetjmp 登记，release 前恒有效
                    unsafe { siglongjmp(jbuf, ret) };
                }
            }
        }
        // 未命中当前线程：让链上一个 handler 接管
        if let Some(prev) = prev_for(signum) {
            let prev_ptr = prev.load(Ordering::Acquire);
            if !prev_ptr.is_null() {
                // SAFETY: prev_ptr 指向 install 的堆分配 sigaction
                unsafe { call_previous(prev_ptr, signum, info, ctx) };
                return;
            }
        }
    }
    // 未接管：恢复 SIG_DFL 并 raise，让内核默认行为接管
    // SAFETY: 信号路径内的简单 syscall 序列
    unsafe {
        let mut dfl: libc::sigaction = core::mem::zeroed();
        libc::sigemptyset(&mut dfl.sa_mask);
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(signum, &dfl, ptr::null_mut());
        libc::raise(signum);
    }
}

unsafe fn call_previous(
    prev_ptr: *const libc::sigaction,
    signum: c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut c_void,
) {
    // SAFETY: prev_ptr 在 install 时填好且不再写
    let prev = unsafe { &*prev_ptr };
    let h = prev.sa_sigaction;
    if h == libc::SIG_DFL || h == libc::SIG_IGN {
        return;
    }
    if (prev.sa_flags & libc::SA_SIGINFO) != 0 {
        // SAFETY: SA_SIGINFO 语义下 handler 为 3 参
        let f: extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void) =
            unsafe { core::mem::transmute(h) };
        f(signum, info, ctx);
    } else {
        // SAFETY: 无 SA_SIGINFO 时 handler 仅接 signum
        let f: extern "C" fn(c_int) = unsafe { core::mem::transmute(h) };
        f(signum);
    }
}

pub unsafe fn guard<F, R>(f: F) -> Result<R, Errno>
where
    F: FnOnce() -> R,
{
    if !INSTALLED.load(Ordering::Acquire) {
        return Err(Errno::Uninit);
    }
    let tid = current_tid();
    let mut jbuf = SigJmpBuf::zeroed();
    let jbuf_ptr: *mut SigJmpBuf = &mut jbuf;

    let idx_segv = occupy_slot(&SEGV_SLOTS, tid, jbuf_ptr)?;
    let idx_bus = match occupy_slot(&BUS_SLOTS, tid, jbuf_ptr) {
        Ok(i) => i,
        Err(e) => {
            release_slot(&SEGV_SLOTS, idx_segv, tid);
            return Err(e);
        }
    };
    let idx_ill = match occupy_slot(&ILL_SLOTS, tid, jbuf_ptr) {
        Ok(i) => i,
        Err(e) => {
            release_slot(&SEGV_SLOTS, idx_segv, tid);
            release_slot(&BUS_SLOTS, idx_bus, tid);
            return Err(e);
        }
    };

    // SAFETY: sigsetjmp 保存上下文；siglongjmp 回跳时 rc 非零
    let rc = unsafe { sigsetjmp(jbuf_ptr, 1) };
    if rc == 0 {
        let ret = f();
        release_slot(&SEGV_SLOTS, idx_segv, tid);
        release_slot(&BUS_SLOTS, idx_bus, tid);
        release_slot(&ILL_SLOTS, idx_ill, tid);
        return Ok(ret);
    }
    // longjmp 路径：f 已被信号中断；清理槽位并返回 crash 错误
    release_slot(&SEGV_SLOTS, idx_segv, tid);
    release_slot(&BUS_SLOTS, idx_bus, tid);
    release_slot(&ILL_SLOTS, idx_ill, tid);
    Err(Errno::HookRewriteCrash)
}

fn occupy_slot(slots: &'static Slots, tid: i32, jbuf: *mut SigJmpBuf) -> Result<usize, Errno> {
    for i in 0..MAX_PROTECTED_THREADS {
        if slots.tids[i]
            .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slots.jbufs[i].store(jbuf, Ordering::Release);
            return Ok(i);
        }
    }
    Err(Errno::NotSupport)
}

fn release_slot(slots: &'static Slots, idx: usize, tid: i32) {
    // 先 null jbuf 再清 tid：handler 命中 tid 时看到 null jbuf 会跳过 longjmp
    slots.jbufs[idx].store(ptr::null_mut(), Ordering::Release);
    let _ = slots.tids[idx].compare_exchange(tid, 0, Ordering::AcqRel, Ordering::Relaxed);
}
