// dump_records 信号场景：在 signal handler 内直接调用 C API dump_records
// 对齐 manual 标注的异步信号安全公开合同

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

use srx_inline_hook::{set_recordable, unhook};

use crate::test_ctx::{STUB_ADD, clear, install, replacement_add, target_add};

unsafe extern "C" {
    fn srx_inline_hook_dump_records(fd: c_int, item_flags: u32);
}

static SIGNAL_DUMP_WR_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn dump_signal_handler(_signum: c_int) {
    let fd = SIGNAL_DUMP_WR_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        unsafe { srx_inline_hook_dump_records(fd, 0x7FF) };
    }
}

fn read_all(fd: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    out
}

pub fn dump_in_signal_handler() {
    let mut fds = [0i32; 2];
    assert_eq!(
        unsafe { libc::pipe(fds.as_mut_ptr()) },
        0,
        "dump_signal check failed"
    );
    let (rd, wr) = (fds[0], fds[1]);

    let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    act.sa_flags = 0;
    act.sa_sigaction = dump_signal_handler as *const () as usize;
    let mut old_act: libc::sigaction = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &act, &mut old_act) },
        0,
        "dump_signal check failed"
    );

    let was_recordable = srx_inline_hook::is_recordable();
    set_recordable(true);
    let stub = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(target_add(2, 3), 1005);
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);

    SIGNAL_DUMP_WR_FD.store(wr, Ordering::SeqCst);
    assert_eq!(
        unsafe { libc::raise(libc::SIGUSR1) },
        0,
        "dump_signal check failed"
    );
    SIGNAL_DUMP_WR_FD.store(-1, Ordering::SeqCst);

    unsafe {
        libc::close(wr);
    }
    let dumped = read_all(rd);
    unsafe {
        libc::close(rd);
        libc::sigaction(libc::SIGUSR1, &old_act, core::ptr::null_mut());
    }
    set_recordable(was_recordable);

    let dumped = String::from_utf8(dumped).expect("signal dump utf8");
    assert!(
        dumped.contains("hook_func_addr") && dumped.contains("unhook"),
        "dump_signal check failed: {}",
        dumped
    );

    println!("dump_in_signal_handler: PASS");
}
