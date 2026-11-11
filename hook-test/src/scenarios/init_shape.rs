// init 只采纳首次 mode / debuggable；后续调用保持幂等
// main 已先以 Unique 初始化，此处验证后续调用不覆盖

use std::env;
use std::process::Command;

use srx_inline_hook::{HookMode, get_init_errno, get_mode, init, is_debug, set_debug};

pub fn init_multi_first_probe() {
    init(HookMode::Multi, false).expect("init multi probe");
    assert_eq!(
        get_init_errno(),
        srx_inline_hook::Errno::Ok,
        "init_shape check failed"
    );
    assert_eq!(get_mode(), HookMode::Multi, "init_shape check failed");
    println!("init_multi_first_probe: PASS");
}

pub fn init_multi_first_process() {
    let exe = env::current_exe().expect("current_exe");
    let exe_dir = exe.parent().expect("exe parent");
    let output = Command::new(&exe)
        .current_dir(exe_dir)
        .arg("--probe-init-multi")
        .output()
        .expect("spawn multi init probe");
    assert!(
        output.status.success(),
        "init_shape command failed: {}, {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("probe stdout utf8");
    assert!(
        stdout.contains("init_multi_first_probe: PASS"),
        "init_shape check failed: {}",
        stdout
    );
    println!("init_multi_first_process: PASS");
}

pub fn init_idempotent() {
    assert_eq!(get_mode(), HookMode::Unique, "init_shape check failed");
    assert!(!is_debug(), "init_shape check failed");

    // 二次 init 尝试切 Shared + debug：mode 与 debuggable 均不覆盖
    // INITED 后不再跑初始化
    init(HookMode::Shared, true).expect("init again");
    assert_eq!(get_mode(), HookMode::Unique, "init_shape check failed");
    assert!(!is_debug(), "init_shape check failed");

    // 要调整 debug 只能显式走 set_debug，不能再靠 init 副作用
    set_debug(true);
    assert!(is_debug(), "init_shape check failed");
    set_debug(false);
    assert!(!is_debug());
    println!("init_idempotent: PASS");
}
