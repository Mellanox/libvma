/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_TCP_BASE_H_
#define TESTS_GTEST_TCP_BASE_H_


/**
 * TCP Base class for tests
 */
class tcp_base : virtual public testing::Test, virtual public test_base {
public:
    static int sock_create(bool reuse_addr = false);
    static int sock_create_nb(void);

protected:
	virtual void SetUp();
	virtual void TearDown();
	void peer_wait(int fd) {
		char keep_alive_check = 1;
		struct timeval tv;

		tv.tv_sec = 3;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
		while (0 < send(fd, &keep_alive_check, sizeof(keep_alive_check), MSG_NOSIGNAL)) {
			usleep(100);
		}
		return ;
	}
};

#endif /* TESTS_GTEST_TCP_BASE_H_ */
