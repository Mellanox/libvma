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


#ifndef ASMARM64_H_
#define ASMARM64_H_

#include <stdint.h>
#include <unistd.h>

#define COPY_64B_NT(dst, src)	\
	*dst++ = *src++;	\
	*dst++ = *src++;	\
	*dst++ = *src++;	\
	*dst++ = *src++;	\
	*dst++ = *src++;	\
	*dst++ = *src++;	\
	*dst++ = *src++;	\
	*dst++ = *src++

#define mb()	asm volatile("dsb sy" ::: "memory")
#define rmb()	asm volatile("dsb ld" ::: "memory")
#define wmb()	asm volatile("dsb st" ::: "memory")
#define wc_wmb() wmb()

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
