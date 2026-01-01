/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2014-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef ASMPPC64_H_
#define ASMPPC64_H_

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

#define mb()	 asm volatile("sync" ::: "memory")
#define rmb()	 asm volatile("lwsync" ::: "memory")
#define wmb()	 rmb()
#define wc_wmb() mb()

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param v pointer of type atomic_t.
 * @return Value before add.
 */
static inline int atomic_fetch_and_add(int i, volatile int *ptr)
{
#ifdef __ATOMIC_ACQUIRE
	return __atomic_fetch_add(ptr, i, __ATOMIC_ACQUIRE);
#else
        return __sync_fetch_and_add(ptr, i);
#endif
}


/**
 * Read RDTSC register
 */
static inline void gettimeoftsc(unsigned long long *p_tscval)
{
	asm volatile ("mftb %0" : "=r" (*p_tscval) : );
}

/**
 * Cache Line Prefetch - Arch specific!
 */
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES		128
#endif

static inline void prefetch(void *x)
{
	//__builtin_prefetch();
	__asm__ __volatile__ ("dcbt 0,%0,1" : : "r" (x));
}

static inline void prefetch_range(void *addr, size_t len)
{
	char *cp = (char*)addr;
	char *end = (char*)addr + len;
	for (; cp < end; cp += L1_CACHE_BYTES)
		prefetch(cp);
}



#endif
