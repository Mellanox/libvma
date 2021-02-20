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

#ifndef TESTS_GTEST_COMMON_DEF_H_
#define TESTS_GTEST_COMMON_DEF_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>   /* printf PRItn */
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/wait.h>    // WIFEXITED, etc.
#include <sys/eventfd.h>
#include <sys/prctl.h> // prctl(), PR_SET_PDEATHSIG
#include <sys/sendfile.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <inttypes.h>   /* printf PRItn */
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>
#include <malloc.h>
#include <math.h>
#include <complex.h>
#include <time.h>
#include <signal.h>

#include "googletest/include/gtest/gtest.h"

#include "config.h"

#define INLINE  __inline

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) ((void)P)
#endif

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))


/* Platform specific 16-byte alignment macro switch.
   On Visual C++ it would substitute __declspec(align(16)).
   On GCC it substitutes __attribute__((aligned (16))).
*/

#if defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((aligned (x)))
#endif

#if !defined( EOK )
#define EOK 0         /* no error */
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) (type *)((char *)(ptr) - offsetof(type,member))
#endif

#define UNDEFINED_VALUE (-1)

struct gtest_configure_t {
	int log_level;
	int random_seed;
	struct sockaddr_in client_addr;
	struct sockaddr_in server_addr;
	struct sockaddr_in remote_addr;
	uint16_t port;
};

#endif /* TESTS_GTEST_COMMON_DEF_H_ */
