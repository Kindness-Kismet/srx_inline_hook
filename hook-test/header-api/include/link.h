#ifndef SRX_INLINE_HOOK_HEADER_COMPAT_LINK_H
#define SRX_INLINE_HOOK_HEADER_COMPAT_LINK_H

#include <stddef.h>

struct dl_phdr_info {
  const char *dlpi_name;
  void *dlpi_addr;
};

#endif
