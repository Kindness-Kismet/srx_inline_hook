#[cfg(target_os = "android")]
use std::env;

#[cfg(target_os = "android")]
mod scenarios;
#[cfg(target_os = "android")]
mod test_ctx;

#[cfg(target_os = "android")]
fn main() {
    println!("{}", srx_inline_hook::get_version());
    if env::args().nth(1).as_deref() == Some("--probe-init-multi") {
        scenarios::init_shape::init_multi_first_probe();
        return;
    }
    srx_inline_hook::init(srx_inline_hook::HookMode::Unique, false).expect("init");
    assert_eq!(
        srx_inline_hook::get_init_errno(),
        srx_inline_hook::Errno::Ok,
        "main check failed"
    );
    scenarios::run_all();
    println!("hook-test: ALL PASS");
}

#[cfg(not(target_os = "android"))]
fn main() {
    println!("{}", srx_inline_hook::get_version());
    println!("hook-test only runs on Android targets");
}
