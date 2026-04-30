#include "srx_inline_hook.h"

typedef int (*add_fn_t)(int, int);

extern void *srx_inline_hook_get_prev_func(void *func);

static int proxy_c(int a, int b) {
  return SRX_INLINE_HOOK_CALL_PREV(proxy_c, add_fn_t, a, b);
}

int main(void) {
  return proxy_c(1, 2);
}
