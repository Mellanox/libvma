/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef ASMARM64_H_
#define ASMARM64_H_

#include <stdint.h>
#include <unistd.h>

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param v pointer of type atomic_t.
 * @return Value before add.
 */
static inline int atomic_fetch_and_add(int i, volatile int *ptr)
{
	return __atomic_fetch_add(ptr, i, __ATOMIC_ACQUIRE);
}

/**
 * Read RDTSC register
 */
static inline void gettimeoftsc(unsigned long long *p_tscval)
{
	// Read Time Stamp Counter
	asm volatile("isb" : : : "memory");
	asm volatile("mrs %0, cntvct_el0" : "=r" ((unsigned long long)*p_tscval));
}

/**
 * Cache Line Prefetch - Arch specific!
 */
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES		64
#endif

static inline void prefetch(void *x)
{
	//__builtin_prefetch();
	asm volatile("prfm pldl1keep, %a0\n" : : "p" (x));
}

static inline void prefetch_range(void *addr, size_t len)
{
	char *cp = (char*)addr;
	char *end = (char*)addr + len;
	for (; cp < end; cp += L1_CACHE_BYTES)
		prefetch(cp);
}



#endif
