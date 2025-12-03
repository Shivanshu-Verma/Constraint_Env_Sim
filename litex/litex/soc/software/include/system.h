#pragma once

#include <stddef.h>
#if defined(__has_include_next)
#  if __has_include_next(<system.h>)
#    include_next <system.h>
#  endif
#else
#  include_next <system.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAS_CLEAN_CPU_DCACHE_RANGE
static inline void clean_cpu_dcache_range(void *start_addr, size_t size)
{
        flush_cpu_dcache();
}
#endif

#ifndef HAS_FLUSH_CPU_DCACHE_RANGE
static inline void flush_cpu_dcache_range(void *start_addr, size_t size)
{
        flush_cpu_dcache();
}
#endif

#ifndef HAS_INVD_CPU_DCACHE_RANGE
static inline void invd_cpu_dcache_range(void *start_addr, size_t size)
{
        flush_cpu_dcache();
}
#endif

#ifdef __cplusplus
}
#endif
