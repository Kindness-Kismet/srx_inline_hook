// 单线程重复安装：同 target 反复 hook/unhook，验证资源归还
// 串行执行规避安装/卸载窗口，交替覆盖 func_addr 与 sym_addr 记录路径

use core::ffi::c_void;

use srx_inline_hook::{HookStub, active_hook_count, hook_single, hook_sym_addr, trampoline_stats};

use crate::test_ctx::{STUB_ADD, clear, replacement_add, target_add};

const ROUNDS: usize = 300;

pub fn single_thread_repeated_hook() {
    let baseline_hooks = active_hook_count();
    let baseline = trampoline_stats();
    let baseline_used = baseline.slots_used;

    let mut peak_pages = 0usize;
    for i in 0..ROUNDS {
        // 交替使用两条入口，覆盖不同记录标签
        let stub: HookStub = if i % 2 == 0 {
            // SAFETY: target / replacement 为本进程可执行地址
            unsafe { hook_single(target_add as *mut c_void, replacement_add as *const c_void) }
                .expect("hook_single")
        } else {
            // SAFETY: 同上
            unsafe {
                hook_sym_addr(
                    target_add as *mut c_void,
                    replacement_add as *const c_void,
                    core::ptr::null_mut(),
                )
            }
            .expect("hook_sym_addr")
        };
        *STUB_ADD.lock().expect("lock") = Some(stub);
        assert_eq!(
            active_hook_count(),
            baseline_hooks + 1,
            "repeated_hook check failed: {}",
            i
        );
        assert_eq!(target_add(1, 2), 1003);

        // SAFETY: stub 有效
        unsafe { srx_inline_hook::unhook(stub).expect("unhook") };
        clear(&STUB_ADD);
        assert_eq!(
            active_hook_count(),
            baseline_hooks,
            "repeated_hook check failed: {}",
            i
        );

        let s = trampoline_stats();
        if s.pages > peak_pages {
            peak_pages = s.pages;
        }
    }

    let final_stats = trampoline_stats();
    assert_eq!(
        final_stats.slots_used, baseline_used,
        "repeated_hook check failed: {}, {}, {}",
        ROUNDS, final_stats.slots_used, baseline_used
    );
    // 冷却窗口内每轮最多增加一个槽，按实际页容量约束增长。
    let slots_per_page = final_stats.slots_total / final_stats.pages;
    assert!(
        peak_pages <= baseline.pages + ROUNDS.div_ceil(slots_per_page),
        "repeated_hook check failed: {}",
        peak_pages
    );
    println!(
        "single_thread_repeated_hook: PASS (rounds={} peak_pages={} slots_used={})",
        ROUNDS, peak_pages, final_stats.slots_used
    );
}
