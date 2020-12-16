/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef ASMX86_H_
#define ASMX86_H_

#include <stdint.h>
#include <unistd.h>
#include "utils/bullseye.h"

#define __xg(x) ((volatile long *)(x))

#define mb()	 asm volatile("" ::: "memory")
#define rmb()	 mb()
#define wmb()	 asm volatile("" ::: "memory")
#define wc_wmb() asm volatile("sfence" ::: "memory")

#define COPY_64B_NT(dst, src)		\
	__asm__ __volatile__ (		\
	" movdqa   (%1),%%xmm0\n"	\
	" movdqa 16(%1),%%xmm1\n"	\
	" movdqa 32(%1),%%xmm2\n"	\
	" movdqa 48(%1),%%xmm3\n"	\
	" movntdq %%xmm0,   (%0)\n"	\
	" movntdq %%xmm1, 16(%0)\n"	\
	" movntdq %%xmm2, 32(%0)\n"	\
	" movntdq %%xmm3, 48(%0)\n"	\
	: : "r" (dst), "r" (src) : "memory");	\
	dst += 8;			\
	src += 8

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
	uint32_t upper_32, lower_32;

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
