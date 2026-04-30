// diagnose 场景：一次性打印库状态快照，验证关键字段与 hook 进度吻合

use srx_inline_hook::{Errno, HookMode, diagnose, get_mode, get_version, unhook};

use crate::test_ctx::{STUB_ADD, clear, install, replacement_add, target_add};

pub fn diagnose_snapshot() {
    let before = diagnose();
    assert_eq!(before.init_errno, Errno::Ok, "diagnose check failed");
    assert_eq!(before.mode, HookMode::Unique, "diagnose check failed");
    assert_eq!(get_mode(), HookMode::Unique);
    assert!(
        !before.version.is_empty(),
        "diagnose check failed: {:?}",
        before.version
    );
    let before_hooks = before.active_hooks;
    let before_tramp_used = before.trampoline.slots_used;

    let stub = install(&STUB_ADD, target_add, replacement_add);
    assert_eq!(target_add(2, 3), 1005);

    let during = diagnose();
    assert_eq!(
        during.active_hooks,
        before_hooks + 1,
        "diagnose check failed"
    );
    assert_eq!(
        during.trampoline.slots_used,
        before_tramp_used + 1,
        "diagnose check failed"
    );

    // Display 一行诊断文本包含版本头
    let line = format!("{}", during);
    let expected_prefix = format!("{} ", get_version());
    assert!(
        line.starts_with(&expected_prefix),
        "diagnose check failed: {}",
        line
    );
    assert!(
        line.contains("hooks=") && line.contains("tramp("),
        "diagnose check failed: {}",
        line
    );
    assert!(line.contains("tls="), "diagnose check failed: {}", line);
    assert!(line.contains("rec_err="), "diagnose check failed: {}", line);
    assert!(!during.record_error, "diagnose check failed");
    assert_eq!(
        during.tls_errno,
        Errno::Ok,
        "diagnose check failed: {:?}",
        during.tls_errno
    );

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);

    let after = diagnose();
    assert_eq!(after.active_hooks, before_hooks, "diagnose check failed");

    println!("diagnose_snapshot: PASS ({})", line);
}
