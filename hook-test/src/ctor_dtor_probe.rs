#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(target_os = "android", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".pushsection .data,\"aw\",@progbits",
    ".balign 8",
    ".local ctor_dtor_probe_symtab_only",
    ".type ctor_dtor_probe_symtab_only, @object",
    ".size ctor_dtor_probe_symtab_only, 8",
    "ctor_dtor_probe_symtab_only:",
    "    .quad 0x1122334455667788",
    ".popsection",
);

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
core::arch::global_asm!(
    ".pushsection .data,\"aw\",@progbits",
    ".balign 8",
    ".local ctor_dtor_probe_symtab_only",
    ".type ctor_dtor_probe_symtab_only, %object",
    ".size ctor_dtor_probe_symtab_only, 8",
    "ctor_dtor_probe_symtab_only:",
    "    .xword 0x1122334455667788",
    ".popsection",
);

#[cfg(target_os = "android")]
unsafe extern "C" {
    static ctor_dtor_probe_symtab_only: u8;
}

#[cfg(not(target_os = "android"))]
#[used]
static CTOR_DTOR_PROBE_SYMTAB_ONLY_HOST: u64 = 0x1122_3344_5566_7788;

static CTOR_HITS: AtomicUsize = AtomicUsize::new(0);
static DTOR_HITS: AtomicUsize = AtomicUsize::new(0);

#[used]
#[unsafe(link_section = ".init_array")]
static INIT_ARRAY: extern "C" fn() = ctor_entry;

#[used]
#[unsafe(link_section = ".fini_array")]
static FINI_ARRAY: extern "C" fn() = dtor_entry;

extern "C" fn ctor_entry() {
    CTOR_HITS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn dtor_entry() {
    DTOR_HITS.fetch_add(1, Ordering::SeqCst);
}

#[unsafe(no_mangle)]
pub extern "C" fn ctor_dtor_probe_add(a: c_int, b: c_int) -> c_int {
    a + b
}

#[unsafe(no_mangle)]
pub extern "C" fn ctor_dtor_probe_mul(a: c_int, b: c_int) -> c_int {
    a * b
}

#[unsafe(no_mangle)]
pub extern "C" fn ctor_dtor_probe_ctor_hits() -> usize {
    CTOR_HITS.load(Ordering::SeqCst)
}

#[unsafe(no_mangle)]
pub extern "C" fn ctor_dtor_probe_dtor_hits() -> usize {
    DTOR_HITS.load(Ordering::SeqCst)
}

#[unsafe(no_mangle)]
pub extern "C" fn ctor_dtor_probe_symtab_only_addr() -> *mut c_void {
    #[cfg(target_os = "android")]
    {
        core::ptr::addr_of!(ctor_dtor_probe_symtab_only) as *mut c_void
    }
    #[cfg(not(target_os = "android"))]
    {
        core::ptr::addr_of!(CTOR_DTOR_PROBE_SYMTAB_ONLY_HOST) as *mut c_void
    }
}
