// monitor_dlopen：注册 init/fini 回调后，dlopen/dlclose 测试 so 应收到 pre/post 通知

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

static INIT_PRE_HITS: AtomicUsize = AtomicUsize::new(0);
static INIT_POST_HITS: AtomicUsize = AtomicUsize::new(0);
static FINI_PRE_HITS: AtomicUsize = AtomicUsize::new(0);
static FINI_POST_HITS: AtomicUsize = AtomicUsize::new(0);
static INIT_PRE_DATA: AtomicUsize = AtomicUsize::new(0);
static INIT_POST_DATA: AtomicUsize = AtomicUsize::new(0);
static FINI_PRE_DATA: AtomicUsize = AtomicUsize::new(0);
static FINI_POST_DATA: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn srx_inline_hook_register_dl_init_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> i32;
    fn srx_inline_hook_unregister_dl_init_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> i32;
    fn srx_inline_hook_register_dl_fini_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> i32;
    fn srx_inline_hook_unregister_dl_fini_callback(
        pre: *mut c_void,
        post: *mut c_void,
        data: *mut c_void,
    ) -> i32;
}

unsafe extern "C" fn init_pre(info: *mut libc::dl_phdr_info, _size: usize, data: *mut c_void) {
    if matches_probe(info) {
        INIT_PRE_HITS.fetch_add(1, Ordering::SeqCst);
        INIT_PRE_DATA.store(data as usize, Ordering::SeqCst);
    }
}

unsafe extern "C" fn init_post(info: *mut libc::dl_phdr_info, _size: usize, data: *mut c_void) {
    if matches_probe(info) {
        INIT_POST_HITS.fetch_add(1, Ordering::SeqCst);
        INIT_POST_DATA.store(data as usize, Ordering::SeqCst);
    }
}

unsafe extern "C" fn fini_pre(info: *mut libc::dl_phdr_info, _size: usize, data: *mut c_void) {
    if matches_probe(info) {
        FINI_PRE_HITS.fetch_add(1, Ordering::SeqCst);
        FINI_PRE_DATA.store(data as usize, Ordering::SeqCst);
    }
}

unsafe extern "C" fn fini_post(info: *mut libc::dl_phdr_info, _size: usize, data: *mut c_void) {
    if matches_probe(info) {
        FINI_POST_HITS.fetch_add(1, Ordering::SeqCst);
        FINI_POST_DATA.store(data as usize, Ordering::SeqCst);
    }
}

fn matches_probe(info: *mut libc::dl_phdr_info) -> bool {
    if info.is_null() {
        return false;
    }
    let info = unsafe { &*info };
    if info.dlpi_name.is_null() {
        return false;
    }
    let Ok(name) = (unsafe { core::ffi::CStr::from_ptr(info.dlpi_name) }).to_str() else {
        return false;
    };
    name.ends_with("libctor_dtor_probe.so")
}

pub fn monitor_dlopen_callbacks() {
    INIT_PRE_HITS.store(0, Ordering::SeqCst);
    INIT_POST_HITS.store(0, Ordering::SeqCst);
    FINI_PRE_HITS.store(0, Ordering::SeqCst);
    FINI_POST_HITS.store(0, Ordering::SeqCst);
    INIT_PRE_DATA.store(0, Ordering::SeqCst);
    INIT_POST_DATA.store(0, Ordering::SeqCst);
    FINI_PRE_DATA.store(0, Ordering::SeqCst);
    FINI_POST_DATA.store(0, Ordering::SeqCst);

    let mut marker = 0x1234usize;
    let marker_ptr = &mut marker as *mut usize as *mut c_void;
    let init_pre_ptr = init_pre as *mut c_void;
    let init_post_ptr = init_post as *mut c_void;
    let fini_pre_ptr = fini_pre as *mut c_void;
    let fini_post_ptr = fini_post as *mut c_void;

    assert_eq!(
        unsafe {
            srx_inline_hook_register_dl_init_callback(init_pre_ptr, init_post_ptr, marker_ptr)
        },
        0,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        unsafe {
            srx_inline_hook_register_dl_fini_callback(fini_pre_ptr, fini_post_ptr, marker_ptr)
        },
        0,
        "monitor_dlopen check failed"
    );

    // SAFETY: 测试 so 与主程序同目录
    let handle = unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "monitor_dlopen check failed");
    // SAFETY: handle 来自成功 dlopen
    unsafe { libc::dlclose(handle) };

    assert!(
        INIT_PRE_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert!(
        INIT_POST_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert!(
        FINI_PRE_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert!(
        FINI_POST_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        INIT_PRE_DATA.load(Ordering::SeqCst),
        marker_ptr as usize,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        INIT_POST_DATA.load(Ordering::SeqCst),
        marker_ptr as usize,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        FINI_PRE_DATA.load(Ordering::SeqCst),
        marker_ptr as usize,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        FINI_POST_DATA.load(Ordering::SeqCst),
        marker_ptr as usize,
        "monitor_dlopen check failed"
    );

    assert_eq!(
        unsafe {
            srx_inline_hook_unregister_dl_init_callback(init_pre_ptr, init_post_ptr, marker_ptr)
        },
        0,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        unsafe {
            srx_inline_hook_unregister_dl_fini_callback(fini_pre_ptr, fini_post_ptr, marker_ptr)
        },
        0,
        "monitor_dlopen check failed"
    );

    INIT_PRE_HITS.store(0, Ordering::SeqCst);
    INIT_POST_HITS.store(0, Ordering::SeqCst);
    FINI_PRE_HITS.store(0, Ordering::SeqCst);
    FINI_POST_HITS.store(0, Ordering::SeqCst);
    INIT_PRE_DATA.store(0, Ordering::SeqCst);
    INIT_POST_DATA.store(0, Ordering::SeqCst);
    FINI_PRE_DATA.store(0, Ordering::SeqCst);
    FINI_POST_DATA.store(0, Ordering::SeqCst);

    let mut post_only_marker = 0x5678usize;
    let post_only_ptr = &mut post_only_marker as *mut usize as *mut c_void;
    assert_eq!(
        unsafe {
            srx_inline_hook_register_dl_init_callback(
                core::ptr::null_mut(),
                init_post_ptr,
                post_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        unsafe {
            srx_inline_hook_register_dl_fini_callback(
                core::ptr::null_mut(),
                fini_post_ptr,
                post_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );

    let post_only_handle =
        unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!post_only_handle.is_null(), "monitor_dlopen check failed");
    unsafe { libc::dlclose(post_only_handle) };

    assert_eq!(
        INIT_PRE_HITS.load(Ordering::SeqCst),
        0,
        "monitor_dlopen check failed"
    );
    assert!(
        INIT_POST_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        FINI_PRE_HITS.load(Ordering::SeqCst),
        0,
        "monitor_dlopen check failed"
    );
    assert!(
        FINI_POST_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        INIT_POST_DATA.load(Ordering::SeqCst),
        post_only_ptr as usize,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        FINI_POST_DATA.load(Ordering::SeqCst),
        post_only_ptr as usize,
        "monitor_dlopen check failed"
    );

    assert_eq!(
        unsafe {
            srx_inline_hook_unregister_dl_init_callback(
                core::ptr::null_mut(),
                init_post_ptr,
                post_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        unsafe {
            srx_inline_hook_unregister_dl_fini_callback(
                core::ptr::null_mut(),
                fini_post_ptr,
                post_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );

    INIT_PRE_HITS.store(0, Ordering::SeqCst);
    INIT_POST_HITS.store(0, Ordering::SeqCst);
    FINI_PRE_HITS.store(0, Ordering::SeqCst);
    FINI_POST_HITS.store(0, Ordering::SeqCst);
    INIT_PRE_DATA.store(0, Ordering::SeqCst);
    INIT_POST_DATA.store(0, Ordering::SeqCst);
    FINI_PRE_DATA.store(0, Ordering::SeqCst);
    FINI_POST_DATA.store(0, Ordering::SeqCst);

    let mut pre_only_marker = 0x9abcusize;
    let pre_only_ptr = &mut pre_only_marker as *mut usize as *mut c_void;
    assert_eq!(
        unsafe {
            srx_inline_hook_register_dl_init_callback(
                init_pre_ptr,
                core::ptr::null_mut(),
                pre_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        unsafe {
            srx_inline_hook_register_dl_fini_callback(
                fini_pre_ptr,
                core::ptr::null_mut(),
                pre_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );

    let pre_only_handle =
        unsafe { libc::dlopen(c"./libctor_dtor_probe.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!pre_only_handle.is_null(), "monitor_dlopen check failed");
    unsafe { libc::dlclose(pre_only_handle) };

    assert!(
        INIT_PRE_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        INIT_POST_HITS.load(Ordering::SeqCst),
        0,
        "monitor_dlopen check failed"
    );
    assert!(
        FINI_PRE_HITS.load(Ordering::SeqCst) >= 1,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        FINI_POST_HITS.load(Ordering::SeqCst),
        0,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        INIT_PRE_DATA.load(Ordering::SeqCst),
        pre_only_ptr as usize,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        FINI_PRE_DATA.load(Ordering::SeqCst),
        pre_only_ptr as usize,
        "monitor_dlopen check failed"
    );

    assert_eq!(
        unsafe {
            srx_inline_hook_unregister_dl_init_callback(
                init_pre_ptr,
                core::ptr::null_mut(),
                pre_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );
    assert_eq!(
        unsafe {
            srx_inline_hook_unregister_dl_fini_callback(
                fini_pre_ptr,
                core::ptr::null_mut(),
                pre_only_ptr,
            )
        },
        0,
        "monitor_dlopen check failed"
    );

    println!(
        "monitor_dlopen_callbacks: PASS (init_pre={} init_post={} fini_pre={} fini_post={})",
        INIT_PRE_HITS.load(Ordering::SeqCst),
        INIT_POST_HITS.load(Ordering::SeqCst),
        FINI_PRE_HITS.load(Ordering::SeqCst),
        FINI_POST_HITS.load(Ordering::SeqCst)
    );
}
