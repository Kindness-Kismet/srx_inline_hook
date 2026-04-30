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

static void pre_cb(srx_inline_hook_cpu_context_t *cpu_context, void *data) {
  (void)cpu_context;
  (void)data;
}

static void intercepted_cb(int error_number, const char *lib_name, const char *sym_name,
                           void *sym_addr, srx_inline_hook_interceptor_t pre, void *data,
                           void *arg) {
  (void)error_number;
  (void)lib_name;
  (void)sym_name;
  (void)sym_addr;
  (void)pre;
  (void)data;
  (void)arg;
}

static void dl_info_cb(struct dl_phdr_info *info, size_t size, void *data) {
  (void)info;
  (void)size;
  (void)data;
}

static int replacement(void) {
  return 0;
}

static srx_inline_hook_hooked_t hooked = hooked_cb;
static srx_inline_hook_interceptor_t interceptor = pre_cb;
static srx_inline_hook_intercepted_t intercepted = intercepted_cb;
static srx_inline_hook_dl_info_t dl_info = dl_info_cb;

int main(void) {
  void *orig = 0;
  void *hook_stub = srx_inline_hook_hook_sym_name_callback_2(
      "libdemo.so", "demo_hook", (void *)replacement, &orig,
      SRX_INLINE_HOOK_HOOK_WITH_MULTI_MODE, hooked, (void *)0x1);
  void *intercept_stub = srx_inline_hook_intercept_sym_name_callback(
      "libdemo.so", "demo_intercept", interceptor, (void *)0x2,
      SRX_INLINE_HOOK_INTERCEPT_DEFAULT, intercepted, (void *)0x3);
  int reg_init = srx_inline_hook_register_dl_init_callback(dl_info, dl_info, (void *)0x4);
  int unreg_init = srx_inline_hook_unregister_dl_init_callback(dl_info, dl_info, (void *)0x4);
  int reg_fini = srx_inline_hook_register_dl_fini_callback(dl_info, dl_info, (void *)0x5);
  int unreg_fini = srx_inline_hook_unregister_dl_fini_callback(dl_info, dl_info, (void *)0x5);
  return (hook_stub != 0) + (intercept_stub != 0) + reg_init + unreg_init + reg_fini + unreg_fini;
}
