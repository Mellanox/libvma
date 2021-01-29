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

#ifndef TESTS_GTEST_COMMON_BASE_H_
#define TESTS_GTEST_COMMON_BASE_H_


/**
 * Base class for tests
 */
class test_base {
public:
	static int sock_noblock(int fd);
	static int event_wait(struct epoll_event *event);
	static int wait_fork(int pid);
	static void handle_signal(int signo);

protected:
	test_base();
	virtual ~test_base();

protected:
	virtual void cleanup();
	virtual void init();
	bool barrier();
	void barrier_fork(int);
	bool child_fork_exit() {
		return m_break_signal;
	}

	struct sockaddr_in client_addr;
	struct sockaddr_in server_addr;
	struct sockaddr_in remote_addr;
	struct sockaddr_in bogus_addr;
	uint16_t port;
	uint16_t bogus_port;

private:
	static void *thread_func(void *arg);

	pthread_barrier_t m_barrier;
	int m_efd;
	uint64_t m_efd_signal;
	static int m_break_signal;
};

#endif /* TESTS_GTEST_COMMON_BASE_H_ */
