// dump_records_to_fd: 与 dump_records_with_items(ALL) 写出的字节完全一致
// 走 pipe 读回，recordable 关时返回 Ok(0)；fd<0 返回 InvalidArg

use core::ffi::c_void;

use srx_inline_hook::{
    Errno, RecordItems, dump_records_to_fd, dump_records_with_items, is_recordable, set_recordable,
    unhook,
};

use crate::test_ctx::{STUB_ADD, clear, install, replacement_add, target_add};

fn read_all(fd: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: fd 为 pipe 读端；buf 足够长
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    out
}

pub fn dump_to_fd_basic() {
    let was_recordable = is_recordable();
    set_recordable(true);

    // 产生几条记录：install + 触发调用 + unhook
    let stub = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(target_add(11, 22), 1033);
    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);

    // 期望：dump_records_to_fd 写出的字节 == dump_records_with_items(ALL)
    let expected = dump_records_with_items(RecordItems::ALL);

    let mut fds = [0i32; 2];
    // SAFETY: pipe 写入两个 fd
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(r, 0, "dump_fd check failed");
    let (rd, wr) = (fds[0], fds[1]);

    let n = dump_records_to_fd(wr, RecordItems::ALL).expect("dump_to_fd");
    assert_eq!(n, expected.len(), "dump_fd check failed");
    // SAFETY: 写端关闭后 read 端读到 EOF 退出循环
    unsafe { libc::close(wr) };

    let got = read_all(rd);
    // SAFETY: 读端关闭回收 fd
    unsafe { libc::close(rd) };

    assert_eq!(got, expected.as_bytes(), "dump_fd check failed");

    // fd 负数：InvalidArg
    let neg = dump_records_to_fd(-1, RecordItems::ALL);
    assert_eq!(neg, Err(Errno::InvalidArg), "dump_fd check failed");

    // recordable 关时：Ok(0) 且不触发 write
    set_recordable(false);
    let mut fds2 = [0i32; 2];
    // SAFETY: 同上
    assert_eq!(unsafe { libc::pipe(fds2.as_mut_ptr()) }, 0);
    let n0 = dump_records_to_fd(fds2[1], RecordItems::ALL).expect("dump when off");
    assert_eq!(n0, 0, "dump_fd check failed");
    // SAFETY: 释放 pipe
    unsafe {
        libc::close(fds2[0]);
        libc::close(fds2[1]);
    }

    // 复原 recordable 开关
    set_recordable(was_recordable);
    println!("dump_to_fd_basic: PASS (wrote={}B)", n);
}
