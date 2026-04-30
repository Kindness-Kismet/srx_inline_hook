// trampoline 池诊断：install/unhook 前后 used 与延迟复用槽位闭环
// active_hook_count 与 slots_used 恒等，两侧观测应一致

use srx_inline_hook::{active_hook_count, trampoline_stats, unhook};

use crate::test_ctx::{STUB_ADD, clear, install, replacement_add, target_add};

pub fn trampoline_stats_basic() {
    let before = trampoline_stats();
    let before_hooks = active_hook_count();
    assert!(before.slots_total > 0, "tramp_stats check failed");
    assert_eq!(
        before.slots_used + before.slots_cooldown + before.slots_free,
        before.slots_total,
        "tramp_stats check failed"
    );
    assert_eq!(
        before.slots_used, before_hooks,
        "tramp_stats check failed: {:?}, {}",
        before, before_hooks
    );

    let stub = install(&STUB_ADD, target_add, replacement_add);
    let after_install = trampoline_stats();
    let after_install_hooks = active_hook_count();
    assert_eq!(
        after_install.slots_used,
        before.slots_used + 1,
        "tramp_stats check failed"
    );
    assert_eq!(
        after_install.slots_used, after_install_hooks,
        "tramp_stats check failed"
    );
    assert_eq!(target_add(5, 7), 1012);

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);
    let after_unhook = trampoline_stats();
    let after_unhook_hooks = active_hook_count();
    assert_eq!(
        after_unhook.slots_used, before.slots_used,
        "tramp_stats check failed"
    );
    assert_eq!(
        after_unhook.slots_used, after_unhook_hooks,
        "tramp_stats check failed"
    );
    assert!(
        after_unhook.slots_cooldown >= before.slots_cooldown + 1,
        "tramp_stats check failed: {:?}, {:?}",
        before,
        after_unhook
    );

    println!(
        "trampoline_stats_basic: PASS (pages={} total={} used={} cooldown={} free={} hooks={})",
        after_unhook.pages,
        after_unhook.slots_total,
        after_unhook.slots_used,
        after_unhook.slots_cooldown,
        after_unhook.slots_free,
        after_unhook_hooks
    );
}
