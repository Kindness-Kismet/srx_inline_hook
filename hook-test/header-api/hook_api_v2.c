#include "srx_inline_hook.h"

static void hooked_cb(int error_number, const char *lib_name, const char *sym_name,
                      void *sym_addr, void *new_addr, void *orig_addr, void *arg) {
  (void)error_number;
  (void)lib_name;
  (void)sym_name;
  (void)sym_addr;
  (void)new_addr;
  (void)orig_addr;
  (void)arg;
}

static int replacement(void) {
  return 0;
}

static int use_hook_api_v2(void) {
  void *orig = 0;
  void *stub1 = srx_inline_hook_hook_func_addr_2((void *)0x1, (void *)replacement, &orig,
                                            SRX_INLINE_HOOK_HOOK_WITH_UNIQUE_MODE |
                                                SRX_INLINE_HOOK_HOOK_RECORD,
                                            "libdemo.so", "demo_func");
  void *stub2 = srx_inline_hook_hook_sym_addr_2((void *)0x2, (void *)replacement, &orig,
                                           SRX_INLINE_HOOK_HOOK_WITH_SHARED_MODE |
                                               SRX_INLINE_HOOK_HOOK_RECORD,
                                           "libdemo.so", "demo_sym");
  void *stub3 = srx_inline_hook_hook_sym_name_2("libdemo.so", "demo_name", (void *)replacement,
                                           &orig, SRX_INLINE_HOOK_HOOK_WITH_MULTI_MODE);
  void *stub4 = srx_inline_hook_hook_sym_name_callback_2(
      "libdemo.so", "demo_name_cb", (void *)replacement, &orig,
      SRX_INLINE_HOOK_HOOK_WITH_MULTI_MODE, hooked_cb, (void *)0x3);
  return (stub1 != 0) + (stub2 != 0) + (stub3 != 0) + (stub4 != 0);
}

int main(void) {
  return use_hook_api_v2();
}
