// 稳态并发：hook 生效后 N 线程并发调用 target 验证视图一致
// 不做并发反复安装；安装/卸载窗口由调用方保证静默

use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::Ordering;
use std::thread;

use srx_inline_hook::unhook;

use crate::test_ctx::{
    HITS_ADD, HITS_MUL, STUB_ADD, STUB_MUL, clear, install, replacement_add, replacement_mul,
    target_add, target_mul,
};

pub fn concurrent_hook_steady() {
    const WORKERS: usize = 4;
    const CALLS_PER_WORKER: usize = 20_000;

    HITS_ADD.store(0, Ordering::SeqCst);
    let stub = install(&STUB_ADD, target_add, replacement_add);

    // hook 已装 + STUB_ADD 写入后再放闸，完全规避安装窗口期
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut handles = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut local = 0u64;
            for _ in 0..CALLS_PER_WORKER {
                let r = target_add(7, 11);
                assert_eq!(r, 1018, "concurrent check failed");
                local += 1;
            }
            local
        }));
    }
    let mut total = 0u64;
    for h in handles {
        total += h.join().expect("join");
    }
    assert_eq!(total as usize, WORKERS * CALLS_PER_WORKER);
    assert!(HITS_ADD.load(Ordering::SeqCst) >= total as usize);

    // SAFETY: stub 有效
    unsafe { unhook(stub).expect("unhook") };
    clear(&STUB_ADD);

    // 卸载后再跑一遍，全部应看到原值
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut handles = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..CALLS_PER_WORKER {
                assert_eq!(target_add(7, 11), 18, "concurrent check failed");
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    println!(
        "concurrent_hook_steady: PASS (calls_per_worker={} workers={})",
        CALLS_PER_WORKER, WORKERS
    );
}

// 两 target 并发：add 与 mul 各 hook 后分流跑，验证 runtime 表不串扰
pub fn concurrent_two_targets() {
    const PAIR_WORKERS: usize = 2;
    const CALLS_PER_WORKER: usize = 20_000;

    HITS_ADD.store(0, Ordering::SeqCst);
    HITS_MUL.store(0, Ordering::SeqCst);
    let stub_add = install(&STUB_ADD, target_add, replacement_add);
    let stub_mul = install(&STUB_MUL, target_mul, replacement_mul);

    let barrier = Arc::new(Barrier::new(PAIR_WORKERS * 2));
    let mut handles = Vec::with_capacity(PAIR_WORKERS * 2);
    for _ in 0..PAIR_WORKERS {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..CALLS_PER_WORKER {
                assert_eq!(target_add(7, 11), 1018, "concurrent check failed");
            }
        }));
    }
    for _ in 0..PAIR_WORKERS {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..CALLS_PER_WORKER {
                // replacement_mul: orig(3,4)+2 = 14
                assert_eq!(target_mul(3, 4), 14, "concurrent check failed");
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    assert!(HITS_ADD.load(Ordering::SeqCst) >= PAIR_WORKERS * CALLS_PER_WORKER);
    assert!(HITS_MUL.load(Ordering::SeqCst) >= PAIR_WORKERS * CALLS_PER_WORKER);

    // SAFETY: 两 stub 有效
    unsafe {
        unhook(stub_add).expect("unhook add");
        unhook(stub_mul).expect("unhook mul");
    }
    clear(&STUB_ADD);
    clear(&STUB_MUL);

    println!(
        "concurrent_two_targets: PASS (pair_workers={} calls_per_worker={})",
        PAIR_WORKERS, CALLS_PER_WORKER
    );
}
