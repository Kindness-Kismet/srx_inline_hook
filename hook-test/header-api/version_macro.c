#include "srx_inline_hook.h"

static const char *version_ptr = SRX_INLINE_HOOK_VERSION;

int main(void) {
  return version_ptr == 0 ? 1 : 0;
}
