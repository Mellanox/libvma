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


#ifndef ASMX86_H_
#define ASMX86_H_

#include <stdint.h>
#include <unistd.h>

#define __xg(x) ((volatile long *)(x))

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
/**
 * Atomic swap
 */
static inline unsigned long xchg(unsigned long x, volatile void *ptr)
{
	__asm__ __volatile__("xchg %0,%1"
			    :"=r" (x)
			    :"m" (*__xg(ptr)), "0" (x)
			    :"memory");
	return x;
}

/**
 * Atomic compare-and-swap
 */
static inline bool cmpxchg(unsigned long old_value, unsigned long new_value, volatile void *ptr)
{
	unsigned long prev_value = old_value;
	__asm__ __volatile__("lock; cmpxchg %1,%2"
			    : "=a"(prev_value)
			    : "r"(new_value), "m"(*__xg(ptr)), "0"(old_value)
			    : "memory");
	return prev_value == old_value;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param v pointer of type atomic_t.
 * @return Value before add.
 */
static inline int atomic_fetch_and_add(int x, volatile int *ptr)
{
	__asm__ __volatile__("lock; xaddl %0,%1"
			    : "=r"(x)
			    : "m"(*ptr), "0"(x)
			    : "memory");
	return x;
}

/**
 * Read RDTSC register
 */
static inline void gettimeoftsc(unsigned long long *p_tscval)
{
	register uint32_t upper_32, lower_32;

	// ReaD Time Stamp Counter (RDTCS)
	__asm__ __volatile__("rdtsc" : "=a" (lower_32), "=d" (upper_32));

	// Copy to user
	*p_tscval = (((unsigned long long)upper_32) << 32) | lower_32;
}

/**
 * Cache Line Prefetch - Arch specific!
 */
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES		64
#endif

static inline void prefetch(void *x)
{
  #if defined __i386__ || defined __x86_64__
	asm volatile("prefetcht0 %0" :: "m" (*(unsigned long *)x));
  #else
	{
		// Use simple memcpy to get data into cache
		char temp_prefetch_block[L1_CACHE_BYTES];
		memcpy(temp_prefetch_block, x, L1_CACHE_BYTES);
	}
  #endif
}

static inline void prefetch_range(void *addr, size_t len)
{
	char *cp = (char*)addr;
	char *end = (char*)addr + len;
	for (; cp < end; cp += L1_CACHE_BYTES)
		prefetch(cp);
}



#endif
