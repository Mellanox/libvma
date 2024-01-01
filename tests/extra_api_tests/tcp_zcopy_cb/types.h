/*
 * Copyright © 2014-2024 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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

#ifndef _TYPES_H_
#define _TYPES_H_

#include <errno.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>

int make_socket_non_blocking (int sfd);
int select_read(int *fd, int sec, int usec);
int sync_side(int sock, int front);

enum callback_return{
	RECV,
	HOLD,
	DROP
} ;

struct  __attribute__ ((packed)) config_t {
  	int                     server;
  	char                    sip[20];
  	char                    mngip[20];
  	int                     port;
  	int                     nonBlocking;
  	int                     reuseAddr;
	enum callback_return	callbackReturn;	
};

struct __attribute__ ((packed)) pending_packet_t{
	int                   valid;
	int                   iovec_size;
	struct iovec          iov[10];
	struct vma_info_t     *vma_info;
};

#define INVALID_SOCKET -1

#define CHECK_VALUE(verb, act_val, exp_val, cmd) if((exp_val) != (act_val)){ \
    printf("Error in %s, expected value %d, actual value %d\n",	\
		 (verb), (exp_val), (act_val));			\
    cmd;                                                                \
  }

#define CHECK_NOT_EQUAL(verb, act_val, exp_val, cmd) if((exp_val) == (act_val)){ \
    printf("Error in %s\n", (verb));						\
    cmd;                                                                \
  }

#endif
