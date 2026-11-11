// 场景路由：run_all 顺序编排 + 每个场景打名
// 新增分组时：新建 scenarios/<name>.rs，在此 pub mod + run 一行

use std::env;

pub mod basic;
pub mod capi;
pub mod concurrent;
pub mod crash_guard;
pub mod diagnose;
pub mod disable_switch;
pub mod dump_fd;
pub mod dump_signal;
pub mod errno_tls;
pub mod error_paths;
pub mod fix_addr;
pub mod init_shape;
pub mod intercept_basic;
pub mod intercept_ctx;
pub mod intercept_sym_addr;
pub mod intercept_sym_name;
pub mod libc;
pub mod linker_probe;
pub mod list_hooks;
pub mod monitor_dlopen;
pub mod multi_chain;
pub mod orig_addr;
#[cfg(target_arch = "aarch64")]
pub mod overlap;
pub mod pending_reopen;
pub mod pending_sym_name;
pub mod records;
pub mod repeated_hook;
pub mod shared_chain;
pub mod shared_stack;
pub mod sym_addr;
pub mod sym_name;
pub mod symbol_info;
pub mod tramp_stats;
pub mod unwind_fp;

pub fn run_all() {
    run("basic", basic::basic);
    run("multi_hook", basic::multi_hook);
    run("multi_chain_basic", multi_chain::multi_chain_basic);
    run("duplicate_hook", basic::duplicate_hook);
    run("unhook_missing", basic::unhook_missing);
    run("rehook_after_unhook", basic::rehook_after_unhook);
    run(
        "init_multi_first_process",
        init_shape::init_multi_first_process,
    );
    run("init_idempotent", init_shape::init_idempotent);
    run(
        "single_thread_repeated_hook",
        repeated_hook::single_thread_repeated_hook,
    );
    run(
        "intercept_func_addr_basic",
        intercept_basic::intercept_func_addr_basic,
    );
    run(
        "intercept_cpu_context_basic",
        intercept_ctx::intercept_cpu_context_basic,
    );
    run(
        "intercept_sym_addr_basic",
        intercept_sym_addr::intercept_sym_addr_basic,
    );
    run(
        "intercept_sym_name_basic",
        intercept_sym_name::intercept_sym_name_basic,
    );
    run(
        "intercept_sym_name_callback_basic",
        intercept_sym_name::intercept_sym_name_callback_basic,
    );
    run(
        "intercept_sym_name_pending_basic",
        intercept_sym_name::intercept_sym_name_pending_basic,
    );
    run(
        "intercept_sym_name_pending_callback_basic",
        intercept_sym_name::intercept_sym_name_pending_callback_basic,
    );
    run(
        "intercept_sym_name_pending_reopen_basic",
        intercept_sym_name::intercept_sym_name_pending_reopen_basic,
    );
    run("hook_libc_strlen", libc::hook_libc_strlen);
    run("concurrent_hook_steady", concurrent::concurrent_hook_steady);
    run("concurrent_two_targets", concurrent::concurrent_two_targets);
    run("hook_with_orig_basic", orig_addr::hook_with_orig_basic);
    run("hook_sym_addr_basic", sym_addr::hook_sym_addr_basic);
    run("hook_sym_name_basic", sym_name::hook_sym_name_basic);
    run(
        "hook_sym_name_callback_basic",
        sym_name::hook_sym_name_callback_basic,
    );
    run(
        "global_disable_switch",
        disable_switch::global_disable_switch,
    );
    run("recordable_dump", records::recordable_dump);
    run("shared_chain_basic", shared_chain::shared_chain_basic);
    run(
        "shared_stack_api_basic",
        shared_stack::shared_stack_api_basic,
    );
    run("dump_to_fd_basic", dump_fd::dump_to_fd_basic);
    run(
        "dump_in_signal_handler",
        dump_signal::dump_in_signal_handler,
    );
    run("addr_info_basic", symbol_info::addr_info_basic);
    run("error_paths", error_paths::error_paths);
    run("crash_guard_sigsegv", crash_guard::crash_guard_sigsegv);
    run("get_errno_basic", errno_tls::get_errno_basic);
    run(
        "trampoline_stats_basic",
        tramp_stats::trampoline_stats_basic,
    );
    run("list_hooks_basic", list_hooks::list_hooks_basic);
    run("diagnose_snapshot", diagnose::diagnose_snapshot);
    run(
        "fix_addr_internal_branch",
        fix_addr::fix_addr_internal_branch,
    );
    run(
        "pending_sym_name_basic",
        pending_sym_name::pending_sym_name_basic,
    );
    run("pending_reopen_basic", pending_reopen::pending_reopen_basic);
    run(
        "linker_base_resolution",
        linker_probe::linker_base_resolution,
    );
    run("linker_dynsym_lookup", linker_probe::linker_dynsym_lookup);
    run("linker_symtab_lookup", linker_probe::linker_symtab_lookup);
    run(
        "linker_hook_installation",
        linker_probe::linker_hook_installation,
    );
    run(
        "monitor_dlopen_callbacks",
        monitor_dlopen::monitor_dlopen_callbacks,
    );
    #[cfg(target_arch = "aarch64")]
    run("hook_overlap_rejection", overlap::hook_overlap_rejection);
    run("capi_state", capi::capi_state);
    run("capi_hook_name", capi::capi_hook_name);
    run("capi_pending", capi::capi_pending);
    run("capi_lookup_flags", capi::capi_lookup_flags);
    run("capi_intercept_addr", capi::capi_intercept_addr);
    run("capi_intercept_name", capi::capi_intercept_name);
    run("capi_callback_contract", capi::capi_callback_contract);
    run("capi_hook_addr_flags", capi::capi_hook_addr_flags);
    run("fp_unwind_basic", unwind_fp::fp_unwind_basic);
}

fn run(name: &str, scenario: fn()) {
    if let Ok(filter) = env::var("HOOK_TEST_SCENARIO")
        && filter != name
    {
        return;
    }
    scenario();
}
