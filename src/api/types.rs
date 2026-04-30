use super::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookStub {
    pub(crate) handle: *mut c_void,
}

impl HookStub {
    pub fn as_ptr(self) -> *mut c_void {
        self.handle
    }
}

// SAFETY: handle 只是全局 stub 池的 opaque id，内部查询受 STUBS 锁保护
unsafe impl Send for HookStub {}
unsafe impl Sync for HookStub {}

// 默认使用 Unique；Shared / Multi 保留模式入口
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum HookMode {
    Shared = 0,
    Unique = 1,
    Multi = 2,
}

pub fn get_mode() -> HookMode {
    match runtime::get_mode() {
        0 => HookMode::Shared,
        2 => HookMode::Multi,
        _ => HookMode::Unique,
    }
}

// prologue 探测上限：一个最长单指令 + 预留
pub(super) const PROLOGUE_PROBE_LEN: usize = 24;
