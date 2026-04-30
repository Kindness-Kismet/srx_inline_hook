#include "srx_inline_hook.h"

extern "C" void *srx_inline_hook_get_prev_func(void *func);

static int proxy_cpp(int a, int b) {
  return SRX_INLINE_HOOK_CALL_PREV(proxy_cpp, a, b);
}

int main() {
  return proxy_cpp(1, 2);
}
