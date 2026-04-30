#include "srx_inline_hook.h"

#include <stdlib.h>

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

static int replacement(void) {
  return 0;
}

int main(void) {
  void *orig = 0;
  const char *version = srx_inline_hook_get_version();
  int init_rc = srx_inline_hook_init(SRX_INLINE_HOOK_MODE_UNIQUE, false);
  int init_errno = srx_inline_hook_get_init_errno();
  srx_inline_hook_mode_t mode = srx_inline_hook_get_mode();
  bool debuggable = srx_inline_hook_get_debuggable();
  bool recordable = srx_inline_hook_get_recordable();
  bool disabled = srx_inline_hook_get_disable();
  int errno_value = srx_inline_hook_get_errno();
  const char *errmsg = srx_inline_hook_to_errmsg(errno_value);

  srx_inline_hook_set_debuggable(!debuggable);
  srx_inline_hook_set_recordable(!recordable);
  srx_inline_hook_set_disable(!disabled);
  srx_inline_hook_set_debuggable(debuggable);
  srx_inline_hook_set_recordable(recordable);
  srx_inline_hook_set_disable(disabled);

  void *hook_func = srx_inline_hook_hook_func_addr((void *)0x1, (void *)replacement, &orig);
  void *hook_sym_addr = srx_inline_hook_hook_sym_addr((void *)0x2, (void *)replacement, &orig);
  void *hook_sym_name = srx_inline_hook_hook_sym_name("libdemo.so", "demo_name",
                                                 (void *)replacement, &orig);
  void *hook_sym_name_cb = srx_inline_hook_hook_sym_name_callback(
      "libdemo.so", "demo_name_cb", (void *)replacement, &orig, hooked_cb, (void *)0x3);
  int unhook_rc = srx_inline_hook_unhook(hook_func);

  void *intercept_instr = srx_inline_hook_intercept_instr_addr((void *)0x4, pre_cb, (void *)0x5,
                                                          SRX_INLINE_HOOK_INTERCEPT_DEFAULT);
  void *intercept_func = srx_inline_hook_intercept_func_addr((void *)0x6, pre_cb, (void *)0x7,
                                                        SRX_INLINE_HOOK_INTERCEPT_DEFAULT);
  void *intercept_sym_addr = srx_inline_hook_intercept_sym_addr((void *)0x8, pre_cb, (void *)0x9,
                                                           SRX_INLINE_HOOK_INTERCEPT_DEFAULT);
  void *intercept_sym_name = srx_inline_hook_intercept_sym_name("libdemo.so", "demo_intercept",
                                                           pre_cb, (void *)0xa,
                                                           SRX_INLINE_HOOK_INTERCEPT_DEFAULT);
  int unintercept_rc = srx_inline_hook_unintercept(intercept_instr);

  char *records = srx_inline_hook_get_records(SRX_INLINE_HOOK_RECORD_ITEM_ALL);
  srx_inline_hook_dump_records(-1, SRX_INLINE_HOOK_RECORD_ITEM_ALL);
  free(records);

  void *handle = srx_inline_hook_dlopen("libdemo.so");
  void *sym_any = srx_inline_hook_dlsym(handle, "demo");
  void *sym_dyn = srx_inline_hook_dlsym_dynsym(handle, "demo");
  void *sym_st = srx_inline_hook_dlsym_symtab(handle, "demo");
  srx_inline_hook_dlclose(handle);

  void *prev = srx_inline_hook_get_prev_func((void *)replacement);
  srx_inline_hook_pop_stack((void *)0xb);
  srx_inline_hook_allow_reentrant((void *)0xc);
  srx_inline_hook_disallow_reentrant((void *)0xd);
  void *ret_addr = srx_inline_hook_get_return_address();

  return (version != 0) + init_rc + init_errno + (int)mode + (errmsg != 0) +
         (hook_func != 0) + (hook_sym_addr != 0) + (hook_sym_name != 0) +
         (hook_sym_name_cb != 0) + unhook_rc + (intercept_instr != 0) +
         (intercept_func != 0) + (intercept_sym_addr != 0) +
         (intercept_sym_name != 0) + unintercept_rc + (sym_any != 0) +
         (sym_dyn != 0) + (sym_st != 0) + (prev != 0) + (ret_addr != 0);
}
