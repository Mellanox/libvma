/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "tcp_base.h"


class tcp_bind : public tcp_base {};

/**
 * @test tcp_bind.ti_1
 * @brief
 *    bind(SOCK_STREAM) socket to local ip
 * @details
 */
TEST_F(tcp_bind, ti_1) {
	int rc = EOK;
	int fd;

	fd = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	close(fd);
}

/**
 * @test tcp_bind.ti_2
 * @brief
 *    bind(SOCK_STREAM) socket to remote ip
 * @details
 */
TEST_F(tcp_bind, ti_2) {
	int rc = EOK;
	int fd;

	fd = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	EXPECT_EQ(EADDRNOTAVAIL, errno);
	EXPECT_GT(0, rc);

	close(fd);
}

/**
 * @test tcp_bind.ti_3
 * @brief
 *    bind(SOCK_STREAM) socket twice
 * @details
 */
TEST_F(tcp_bind, ti_3) {
	int rc = EOK;
	int fd;
	struct sockaddr_in addr1;
	struct sockaddr_in addr2;

	fd = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	memcpy(&addr1, &client_addr, sizeof(addr1));
	addr1.sin_port = htons(17001);
	rc = bind(fd, (struct sockaddr *)&addr1, sizeof(addr1));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	memcpy(&addr2, &client_addr, sizeof(addr2));
	addr2.sin_port = htons(17002);
	rc = bind(fd, (struct sockaddr *)&addr2, sizeof(addr2));
	EXPECT_EQ(EINVAL, errno);
	EXPECT_GT(0, rc);

	close(fd);
}

/**
 * @test tcp_bind.ti_4
 * @brief
 *    bind(SOCK_STREAM) two sockets on the same ip
 * @details
 */
TEST_F(tcp_bind, ti_4) {
	int rc = EOK;
	int fd;
	int fd2;
	struct sockaddr_in addr;

	fd = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	memcpy(&addr, &client_addr, sizeof(addr));
	addr.sin_port = htons(17003);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	fd2 = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd2, (struct sockaddr *)&addr, sizeof(addr));
	EXPECT_EQ(EADDRINUSE, errno);
	EXPECT_GT(0, rc);

	close(fd);
	close(fd2);
}
