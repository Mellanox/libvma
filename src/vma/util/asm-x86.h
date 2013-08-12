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
 * Atomic fetch-and-add
 */
static inline int xaddl(int x, volatile int *ptr)
{
	__asm__ __volatile__("lock; xaddl %0,%1"
			    : "=r"(x)
			    : "m"(*ptr), "0"(x)
			    : "memory");
	return x;
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
