#include "srx_inline_hook.h"

void srx_inline_hook_pop_stack(void *return_address);

static void pop_stack_api(void) {
  SRX_INLINE_HOOK_POP_STACK();
}

int main(void) {
  pop_stack_api();
  return 0;
}
