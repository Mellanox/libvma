/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "tcp_base.h"


class tcp_sendto : public tcp_base {};

/**
 * @test tcp_sendto.ti_1
 * @brief
 *    send() invalid socket fd
 * @details
 */
TEST_F(tcp_sendto, ti_1) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

	fd = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = sendto(0xFF, (void *)buf, sizeof(buf), 0,
			(struct sockaddr *)&server_addr, sizeof(server_addr));
	EXPECT_EQ(EBADF, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test tcp_sendto.ti_2
 * @brief
 *    send() no connection
 * @details
 */
TEST_F(tcp_sendto, ti_2) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

	fd = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	(void)signal(SIGPIPE, SIG_IGN);
	rc = sendto(fd, (void *)buf, sizeof(buf), 0,
			(struct sockaddr *)&server_addr, sizeof(server_addr));
	EXPECT_EQ(EPIPE, errno);
	EXPECT_EQ(-1, rc);
	(void)signal(SIGPIPE, SIG_DFL);

	close(fd);
}
