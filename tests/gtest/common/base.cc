/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "base.h"

test_base::test_base()
{
	port = gtest_conf.port;
	memcpy(&client_addr, &gtest_conf.client_addr, sizeof(client_addr));
	memcpy(&server_addr, &gtest_conf.server_addr, sizeof(server_addr));
	memcpy(&remote_addr, &gtest_conf.remote_addr, sizeof(remote_addr));

	bogus_port = 49999;
	bogus_addr.sin_family = PF_INET;
	bogus_addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	bogus_addr.sin_port = 0;
}

test_base::~test_base()
{
}

void *test_base::thread_func(void *arg)
{
    test_base *self = reinterpret_cast<test_base*>(arg);
    self->barrier(); /* Let all threads start in the same time */
    return NULL;
}

void test_base::init()
{
}

void test_base::cleanup()
{
}

bool test_base::barrier()
{
    int ret = pthread_barrier_wait(&m_barrier);
    if (ret == 0) {
        return false;
    } else if (ret == PTHREAD_BARRIER_SERIAL_THREAD) {
        return true;
    } else {
    	log_fatal("pthread_barrier_wait() failed\n");
    }
    return false;
}

int test_base::sock_noblock(int fd)
{
	int rc = 0;
	int flag;

	flag = fcntl(fd, F_GETFL);
	if (flag < 0) {
		rc = -errno;
		log_error("failed to get socket flags %s\n", strerror(errno));
	}
	flag |= O_NONBLOCK;
	rc = fcntl(fd, F_SETFL, flag);
	if (rc < 0) {
		rc = -errno;
		log_error("failed to set socket flags %s\n", strerror(errno));
	}

	return rc;
}

int test_base::event_wait(struct epoll_event *event)
{
	int rc = 0;
	int fd;
	int efd = -1;
	int timeout = 10 * 1000;

	if (!event) {
		return -1;
	}

	fd = event->data.fd;
	efd = epoll_create1(0);
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, event);
	if (rc < 0) {
		log_error("failed epoll_ctl() %s\n", strerror(errno));
		goto err;
	}

	rc = epoll_wait(efd, event, 1, timeout);
	if (rc < 0) {
		log_error("failed epoll_wait() %s\n", strerror(errno));
	}

	epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);

err:
	close(efd);

	return rc;
}
