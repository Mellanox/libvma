/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_COMMON_BASE_H_
#define TESTS_GTEST_COMMON_BASE_H_

#define DO_WHILE0(x)                                                                               \
    do {                                                                                           \
        x                                                                                          \
    } while (0)

#define EXPECT_LE_ERRNO(val1, val2)                                                                \
    DO_WHILE0(EXPECT_LE((val1), (val2));                                                           \
              if (val1 > val2) { log_trace("Failed. errno = %d\n", errno); })

#define EXPECT_EQ_ERRNO(val1, val2)                                                                \
    DO_WHILE0(EXPECT_EQ((val1), (val2));                                                           \
              if (val1 != val2) { log_trace("Failed. errno = %d\n", errno); })

/**
 * Base class for tests
 */
class test_base {
public:
	static int sock_noblock(int fd);
	static int event_wait(struct epoll_event *event);
	static int wait_fork(int pid);
	static int set_socket_rcv_timeout(int fd, int timeout_sec);
	static void handle_signal(int signo);

protected:
	test_base();
	virtual ~test_base();

protected:
	virtual void cleanup();
	virtual void init();
	bool barrier();
	void barrier_fork(int pid, bool sync_parent = false);
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
