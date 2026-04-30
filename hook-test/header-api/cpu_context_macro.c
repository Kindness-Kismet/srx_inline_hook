#include "srx_inline_hook.h"

static int use_cpu_context_views(void) {
  srx_inline_hook_vreg_t reg = {0};
  reg.d[0] = 1;
  reg.d[1] = 2;
  reg.s[0] ^= 3;
  reg.h[0] ^= 4;
  reg.b[0] ^= 5;
#if defined(__aarch64__)
  reg.q ^= (__uint128_t)6;
#endif
  srx_inline_hook_cpu_context_t ctx = {0};
  ctx.vregs[0] = reg;
  return (int)(ctx.vregs[0].b[0] + ctx.vregs[0].d[1]);
}

int main(void) {
  return use_cpu_context_views() < 0 ? 1 : 0;
}
