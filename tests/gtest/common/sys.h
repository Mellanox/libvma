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

#ifndef TESTS_GTEST_COMMON_SYS_H_
#define TESTS_GTEST_COMMON_SYS_H_

/* Minimum and maximum macros */
#define sys_max(a, b)  (((a) > (b)) ? (a) : (b))
#define sys_min(a, b)  (((a) < (b)) ? (a) : (b))

static INLINE int sys_is_big_endian(void)
{
	return( htonl(1) == 1 );
}

static INLINE double sys_gettime(void)
{
	struct timeval tv;
	gettimeofday(&tv, 0);
	return (double)(tv.tv_sec * 1000000 + tv.tv_usec);
}

static INLINE uint64_t sys_rdtsc(void)
{
	unsigned long long int result=0;

#if defined(__i386__)
	__asm volatile(".byte 0x0f, 0x31" : "=A" (result) : );

#elif defined(__x86_64__)
	unsigned hi, lo;
	__asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	result = hi;
	result = result<<32;
	result = result|lo;

#elif defined(__powerpc__)
	unsigned long int hi, lo, tmp;
	__asm volatile(
	    "0:                 \n\t"
	    "mftbu   %0         \n\t"
	    "mftb    %1         \n\t"
	    "mftbu   %2         \n\t"
	    "cmpw    %2,%0      \n\t"
	    "bne     0b         \n"
	    : "=r"(hi),"=r"(lo),"=r"(tmp)
	    );
	result = hi;
	result = result<<32;
	result = result|lo;

#endif

	return (result);
}

void sys_hexdump(const char *tag, void *ptr, int buflen);

int sys_get_addr(char *dst, struct sockaddr_in *addr);

char *sys_addr2dev(struct sockaddr_in *addr, char *buf, size_t size);

int sys_dev2addr(char *dev, struct sockaddr_in *addr);

int sys_gateway(struct sockaddr_in *addr);

pid_t sys_procpid(const char* name);

static INLINE char *sys_addr2str(struct sockaddr_in *addr)
{
	static char buf[100];
	static __thread char addrbuf[sizeof(buf) + sizeof(addr->sin_port) + 5];
	inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf) - 1);
	sprintf(addrbuf, "%s:%d", buf, ntohs(addr->sin_port));

	return addrbuf;
}

static INLINE int sys_rootuser(void)
{
	return (geteuid() == 0);
}

#endif /* TESTS_GTEST_COMMON_SYS_H_ */
