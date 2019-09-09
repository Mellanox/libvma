/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#define mb()	 asm volatile("" ::: "memory")
#define rmb()	 mb()
#define wmb()	 asm volatile("" ::: "memory")
#define wc_wmb() asm volatile("sfence" ::: "memory")

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param v pointer of type atomic_t.
 * @return Value before add.
 */
#define __vma_atomic_fetch_add_explicit    __x86_atomic_fetch_and_add
static inline int __x86_atomic_fetch_and_add(atomic_t *obj, int val, int order)
{
	(void)order;
	__asm__ __volatile__("lock; xaddl %0,%1"
			    : "=r"(val)
			    : "m"(obj->value), "0"(val)
			    : "memory");
	return val;
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

enum {
    CPU_FLAG_CMOV  = (1 << 0),
    CPU_FLAG_MMX   = (1 << 1),
    CPU_FLAG_MMX2  = (1 << 2),
    CPU_FLAG_SSE   = (1 << 3),
    CPU_FLAG_SSE2  = (1 << 4),
    CPU_FLAG_SSE3  = (1 << 5),
    CPU_FLAG_SSSE3 = (1 << 6),
    CPU_FLAG_SSE41 = (1 << 7),
    CPU_FLAG_SSE42 = (1 << 8),
    CPU_FLAG_AVX   = (1 << 9),
    CPU_FLAG_AVX2  = (1 << 10)
};

#define X86_CPUID_GET_MODEL       0x00000001u
#define X86_CPUID_GET_BASE_VALUE  0x00000000u
#define X86_CPUID_GET_EXTD_VALUE  0x00000007u
#define X86_CPUID_GET_MAX_VALUE   0x80000000u

VMA_ATTRIBUTE_OPTIMIZE_NONE
	static inline void __x86_cpuid(uint32_t level,
		uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	asm volatile ("cpuid\n\t"
				: "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d)
				: "0" (level));
}

/* This allows the CPU detection to work with assemblers not supporting
 * the xgetbv mnemonic.
 */
#define __x86_xgetbv(_index, _eax, _edx) \
	asm volatile (".byte 0x0f, 0x01, 0xd0" : "=a"(_eax), "=d"(_edx) : "c" (_index))

/**
 * Read CPU instruction set
 */
VMA_ATTRIBUTE_OPTIMIZE_NONE
	static inline int cpuid_flags()
{
	static int cpu_flag = -1;

	if (cpu_flag < 0) {
		uint32_t result = 0;
		uint32_t base_value;
		uint32_t _eax, _ebx, _ecx, _edx;

		__x86_cpuid(X86_CPUID_GET_BASE_VALUE, &_eax, &_ebx, &_ecx, &_edx);
		base_value = _eax;

		if (base_value >= 1) {
			__x86_cpuid(X86_CPUID_GET_MODEL, &_eax, &_ebx, &_ecx, &_edx);
			if (_edx & (1 << 15)) {
				result |= CPU_FLAG_CMOV;
			}
			if (_edx & (1 << 23)) {
				result |= CPU_FLAG_MMX;
			}
			if (_edx & (1 << 25)) {
				result |= CPU_FLAG_MMX2;
			}
			if (_edx & (1 << 25)) {
				result |= CPU_FLAG_SSE;
			}
			if (_edx & (1 << 26)) {
				result |= CPU_FLAG_SSE2;
			}
			if (_ecx & 1) {
				result |= CPU_FLAG_SSE3;
			}
			if (_ecx & (1 << 9)) {
				result |= CPU_FLAG_SSSE3;
			}
			if (_ecx & (1 << 19)) {
				result |= CPU_FLAG_SSE41;
			}
			if (_ecx & (1 << 20)) {
				result |= CPU_FLAG_SSE42;
			}
			if ((_ecx & 0x18000000) == 0x18000000) {
				__x86_xgetbv(0, _eax, _edx);
				if ((_eax & 0x6) == 0x6) {
					result |= CPU_FLAG_AVX;
				}
			}
		}
		if (base_value >= 7) {
			__x86_cpuid(X86_CPUID_GET_EXTD_VALUE, &_eax, &_ebx, &_ecx, &_edx);
			if ((result & CPU_FLAG_AVX) && (_ebx & (1 << 5))) {
				result |= CPU_FLAG_AVX2;
			}
		}
		cpu_flag = result;
	}

	return cpu_flag;
}

#define __vma_memory_copy64(_dst, _src) \
{ \
	static int is_wc_simd = cpuid_flags() &                \
			(CPU_FLAG_SSE41 | CPU_FLAG_SSE42);             \
                                                           \
	if (is_wc_simd) {                                      \
		__asm__ __volatile__ (                             \
		" movdqa   (%1),  %%xmm0\n"                        \
		" movdqa 16(%1),  %%xmm1\n"                        \
		" movdqa 32(%1),  %%xmm2\n"                        \
		" movdqa 48(%1),  %%xmm3\n"                        \
                                                           \
		" movntdq %%xmm0,   (%0)\n"                        \
		" movntdq %%xmm1, 16(%0)\n"                        \
		" movntdq %%xmm2, 32(%0)\n"                        \
		" movntdq %%xmm3, 48(%0)\n"                        \
		: : "r" (_dst), "r" (_src) : "memory");            \
		_dst += 8;                                         \
		_src += 8;                                         \
	} else {                                               \
		*_dst++ = *_src++;                                 \
		*_dst++ = *_src++;                                 \
		*_dst++ = *_src++;                                 \
		*_dst++ = *_src++;                                 \
		*_dst++ = *_src++;                                 \
		*_dst++ = *_src++;                                 \
		*_dst++ = *_src++;                                 \
		*_dst++ = *_src++;                                 \
	}                                                      \
}

#endif
