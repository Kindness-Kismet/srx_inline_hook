# srx_inline_hook

`srx_inline_hook` 是面向 Android 运行时的纯 Rust inline hook 引擎，提供 Rust API 与 `srx_inline_hook_*` C ABI。

原参考项目 Git 地址：https://github.com/bytedance/android-inline-hook

## 支持边界

- 架构：`aarch64-linux-android`、`x86_64-linux-android`
- ABI：`arm64-v8a`、`x86_64`
- 最低构建 API：Android API 31（Android 12）
- 目标系统版本：Android 12–17

## 能力概览

- 按函数地址安装 hook：`hook_single` / `srx_inline_hook_hook_func_addr`
- 按符号地址安装 hook：`hook_sym_addr` / `srx_inline_hook_hook_sym_addr`
- 按 so 名和符号名安装 hook：`hook_sym_name` / `srx_inline_hook_hook_sym_name`
- 获取原函数跳板：`prev_func`、`hook_with_orig`、`SRX_INLINE_HOOK_CALL_PREV`
- 指令级 intercept：`intercept_func_addr`、`intercept_sym_addr`、`srx_inline_hook_intercept_*`
- 记录与诊断：`dump_records`、`list_hooks`、`diagnose`、`trampoline_stats`
- linker 辅助：符号查找、加载/卸载回调、pending hook / intercept

## Rust 调用示例

```rust
use core::ffi::c_void;
use std::sync::Mutex;

use srx_inline_hook::{HookMode, HookStub, hook_single, init, prev_func, unhook};

static STUB: Mutex<Option<HookStub>> = Mutex::new(None);

extern "C" fn target_add(a: i64, b: i64) -> i64 {
    a + b
}

extern "C" fn replacement_add(a: i64, b: i64) -> i64 {
    let stub = STUB.lock().unwrap().unwrap();
    let prev = unsafe { prev_func(stub).unwrap() };
    let prev_fn: extern "C" fn(i64, i64) -> i64 = unsafe { core::mem::transmute(prev) };
    prev_fn(a, b) + 1000
}

fn main() {
    init(HookMode::Unique, false).unwrap();

    let stub = unsafe {
        hook_single(
            target_add as *mut c_void,
            replacement_add as *const c_void,
        )
        .unwrap()
    };
    *STUB.lock().unwrap() = Some(stub);

    assert_eq!(target_add(1, 2), 1003);

    unsafe { unhook(stub).unwrap() };
    *STUB.lock().unwrap() = None;
    assert_eq!(target_add(1, 2), 3);
}
```

## C API 调用示例

头文件位于 `include/srx_inline_hook.h`。

```c
#include "srx_inline_hook.h"

#include <stdint.h>
#include <string.h>

static void *g_stub = 0;

typedef size_t (*strlen_t)(const char *s);

static size_t replacement_strlen(const char *s) {
  strlen_t orig = (strlen_t)srx_inline_hook_get_prev_func(g_stub);
  return orig(s) + 100;
}

void install_hook(void) {
  int rc = srx_inline_hook_init(SRX_INLINE_HOOK_MODE_UNIQUE, false);
  if (rc != SRX_INLINE_HOOK_ERRNO_OK) return;

  g_stub = srx_inline_hook_hook_sym_name(
      "libc.so",
      "strlen",
      (void *)replacement_strlen,
      0);
}

void uninstall_hook(void) {
  if (g_stub != 0) {
    srx_inline_hook_unhook(g_stub);
    g_stub = 0;
  }
}
```

## 构建

需要安装 Android SDK、Android NDK 和 `cargo-ndk`。

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android x86_64-linux-android
```

双架构 release 构建：

```bash
ANDROID_HOME=<android-sdk> ANDROID_NDK_HOME=<android-ndk> \
  RUSTFLAGS="-C force-frame-pointers=yes" \
  cargo ndk -t arm64-v8a -t x86_64 --platform 31 build \
  --workspace --release
```

产物位置：

- `target/aarch64-linux-android/release/libsrx_inline_hook.so`
- `target/aarch64-linux-android/release/hook-test`
- `target/aarch64-linux-android/release/libctor_dtor_probe.so`
- `target/x86_64-linux-android/release/libsrx_inline_hook.so`
- `target/x86_64-linux-android/release/hook-test`
- `target/x86_64-linux-android/release/libctor_dtor_probe.so`

## 本地检查

格式检查：

```bash
cargo fmt --all -- --check
```

Host 单元测试只覆盖纯计算逻辑，例如指令长度解码、指令重写和位域编解码：

```bash
cargo test --workspace --lib
```

Android 双架构编译检查：

```bash
RUSTFLAGS="-C force-frame-pointers=yes" cargo check --workspace --target aarch64-linux-android
RUSTFLAGS="-C force-frame-pointers=yes" cargo check --workspace --target x86_64-linux-android
```

## 集成测试流程

`hook-test` 是 Android 集成测试程序。它会按固定顺序运行所有场景，成功时输出：

```text
hook-test: ALL PASS
```

### 推送并运行 arm64 真机

```bash
REMOTE_DIR=/data/local/tmp/srx_inline_hook_test
adb -s <arm64-device-id> shell "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}"
adb -s <arm64-device-id> push target/aarch64-linux-android/release/hook-test ${REMOTE_DIR}/
adb -s <arm64-device-id> push target/aarch64-linux-android/release/libctor_dtor_probe.so ${REMOTE_DIR}/
adb -s <arm64-device-id> push target/aarch64-linux-android/release/libsrx_inline_hook.so ${REMOTE_DIR}/
adb -s <arm64-device-id> shell "chmod 755 ${REMOTE_DIR}/hook-test && cd ${REMOTE_DIR} && LD_LIBRARY_PATH=. ./hook-test"
```

### 推送并运行 x86_64 模拟器

```bash
REMOTE_DIR=/data/local/tmp/srx_inline_hook_test
adb -s <emulator-id> shell "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}"
adb -s <emulator-id> push target/x86_64-linux-android/release/hook-test ${REMOTE_DIR}/
adb -s <emulator-id> push target/x86_64-linux-android/release/libctor_dtor_probe.so ${REMOTE_DIR}/
adb -s <emulator-id> push target/x86_64-linux-android/release/libsrx_inline_hook.so ${REMOTE_DIR}/
adb -s <emulator-id> shell "chmod 755 ${REMOTE_DIR}/hook-test && cd ${REMOTE_DIR} && LD_LIBRARY_PATH=. ./hook-test"
```

### 只运行单个场景

可以用 `HOOK_TEST_SCENARIO` 过滤场景：

```bash
adb -s <device-id> shell \
  "cd /data/local/tmp/srx_inline_hook_test && \
   HOOK_TEST_SCENARIO=capi_intercept_addr LD_LIBRARY_PATH=. ./hook-test"
```
