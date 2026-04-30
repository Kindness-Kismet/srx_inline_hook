#include "srx_inline_hook.h"

extern "C" void srx_inline_hook_pop_stack(void *return_address);
extern "C" void srx_inline_hook_allow_reentrant(void *return_address);
extern "C" void srx_inline_hook_disallow_reentrant(void *return_address);
extern "C" void *srx_inline_hook_get_return_address(void);

static void header_macro_api() {
  SRX_INLINE_HOOK_STACK_SCOPE();
  SRX_INLINE_HOOK_ALLOW_REENTRANT();
  SRX_INLINE_HOOK_DISALLOW_REENTRANT();
  (void)SRX_INLINE_HOOK_RETURN_ADDRESS();
}

int main() {
  header_macro_api();
  return 0;
}
