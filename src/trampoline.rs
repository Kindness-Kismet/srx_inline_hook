// 跳板池：按页 mmap RWX + 固定 slot 分配；free 走延迟复用以兼容仍在执行跳板的线程

use core::ptr::NonNull;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::android;
use crate::errno::Errno;

// 单跳板字节数：容纳 rewrite(最坏 ≈ 80B) + 绝对跳尾部(16B) 有余
pub const TRAMPOLINE_SIZE: usize = 128;
// 延迟复用 10s：避开其他线程仍在 trampoline 内执行的窗口
const REUSE_DELAY_SECS: u32 = 10;

struct Page {
    base: NonNull<u8>,
    page_bytes: usize,
    slot_count: usize,
    // 每 slot 一个 flag：bit31=used；低 31 位=free 时间戳（单调秒）
    flags: Vec<u32>,
}

// SAFETY: Page.base 为 mmap 基址，仅在 POOL 锁保护下访问
unsafe impl Send for Page {}

struct Pool {
    pages: Mutex<Vec<Page>>,
}

static POOL: Lazy<Pool> = Lazy::new(|| Pool {
    pages: Mutex::new(Vec::new()),
});

fn monotonic_secs() -> u32 {
    // 加 86400 偏移避开 ts=0 歧义（flag 低 31 位=0 表示未 release）
    // SAFETY: clock_gettime 仅读取内核时钟
    let mut ts: libc::timespec = unsafe { core::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u32).wrapping_add(24 * 60 * 60)
}

pub fn acquire() -> Result<NonNull<u8>, Errno> {
    let mut pages = POOL.pages.lock().map_err(|_| Errno::NotSupport)?;
    let now = monotonic_secs();
    for page in pages.iter_mut() {
        if let Some(ptr) = try_alloc_in_page(page, now) {
            return Ok(ptr);
        }
    }
    let new = new_page()?;
    pages.push(new);
    let page = pages.last_mut().ok_or(Errno::Oom)?;
    try_alloc_in_page(page, now).ok_or(Errno::Oom)
}

fn try_alloc_in_page(page: &mut Page, now: u32) -> Option<NonNull<u8>> {
    for i in 0..page.slot_count {
        let f = page.flags[i];
        if f >> 31 != 0 {
            continue;
        }
        let ts = f & 0x7FFF_FFFF;
        if ts != 0 && (now <= ts || now - ts <= REUSE_DELAY_SECS) {
            continue;
        }
        page.flags[i] = 0x8000_0000;
        // SAFETY: i < slot_count 保证 slot 位于 page 有效区内
        let slot = unsafe { page.base.as_ptr().add(i * TRAMPOLINE_SIZE) };
        // SAFETY: slot 指向 RWX 页内 TRAMPOLINE_SIZE 字节
        unsafe { core::ptr::write_bytes(slot, 0, TRAMPOLINE_SIZE) };
        return NonNull::new(slot);
    }
    None
}

fn new_page() -> Result<Page, Errno> {
    let page_bytes = android::page_size();
    // SAFETY: nullptr 由内核自选地址
    let raw = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            page_bytes,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(Errno::Oom);
    }
    let base = NonNull::new(raw as *mut u8).ok_or(Errno::Oom)?;
    // SAFETY: base 指向刚 mmap 的匿名页；prctl 失败仅影响诊断命名
    unsafe {
        android::name_anon_page(base.as_ptr(), page_bytes, c"srx_inline_hook_trampo");
    }
    let slot_count = page_bytes / TRAMPOLINE_SIZE;
    Ok(Page {
        base,
        page_bytes,
        slot_count,
        flags: vec![0u32; slot_count],
    })
}

pub fn release(addr: NonNull<u8>) -> Result<(), Errno> {
    let mut pages = POOL.pages.lock().map_err(|_| Errno::NotSupport)?;
    let now = monotonic_secs();
    let target = addr.as_ptr() as usize;
    for page in pages.iter_mut() {
        let base = page.base.as_ptr() as usize;
        let end = base + page.page_bytes;
        if target >= base && target < end {
            let offset = target - base;
            if offset % TRAMPOLINE_SIZE != 0 {
                return Err(Errno::UnhookTrampoMismatch);
            }
            let idx = offset / TRAMPOLINE_SIZE;
            if idx >= page.slot_count || page.flags[idx] >> 31 == 0 {
                return Err(Errno::UnhookTrampoMismatch);
            }
            page.flags[idx] = now & 0x7FFF_FFFF;
            return Ok(());
        }
    }
    Err(Errno::UnhookTrampoMismatch)
}

// 诊断快照：pages/总 slot/占用/冷却/可立即复用
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrampolineStats {
    pub pages: usize,
    pub slots_total: usize,
    pub slots_used: usize,
    pub slots_cooldown: usize,
    pub slots_free: usize,
}

pub fn stats() -> TrampolineStats {
    let Ok(pages) = POOL.pages.lock() else {
        return TrampolineStats::default();
    };
    let now = monotonic_secs();
    let mut s = TrampolineStats::default();
    s.pages = pages.len();
    for page in pages.iter() {
        s.slots_total += page.slot_count;
        for i in 0..page.slot_count {
            let f = page.flags[i];
            if f >> 31 != 0 {
                s.slots_used += 1;
                continue;
            }
            let ts = f & 0x7FFF_FFFF;
            if ts != 0 && (now <= ts || now - ts <= REUSE_DELAY_SECS) {
                s.slots_cooldown += 1;
            } else {
                s.slots_free += 1;
            }
        }
    }
    s
}
