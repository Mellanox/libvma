/*
 * Copyright (c) 2019 Mellanox Technologies, Ltd. All rights reserved.
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
#include "common/base.h"

#include "udp_base.h"


class udp_send : public udp_base {};

/**
 * @test udp_send.ti_1
 * @brief
 *    send() successful call
 * @details
 */
TEST_F(udp_send, ti_1) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = send(fd, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(sizeof(buf), rc);

	close(fd);
}

/**
 * @test udp_send.ti_2
 * @brief
 *    send() invalid socket fd
 * @details
 */
TEST_F(udp_send, ti_2) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = send(0xFF, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EBADF, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test udp_send.ti_3
 * @brief
 *    send() invalid buffer length (>65,507 bytes)
 * @details
 */
TEST_F(udp_send, ti_3) {
	int rc = EOK;
	int fd;
	char buf[65508] = "hello";

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = send(fd, (void *)buf, 65507, 0);
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(65507, rc);

	errno = EOK;
	rc = send(fd, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EMSGSIZE, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test udp_send.ti_4
 * @brief
 *    send() invalid address length
 * @details
 */
TEST_F(udp_send, ti_4) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr) - 1);
	EXPECT_EQ(EINVAL, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test udp_send.ti_5
 * @brief
 *    send() invalid flag set
 * @details
 */
TEST_F(udp_send, ti_5) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = send(fd, (void *)buf, sizeof(buf), 0x000000FF);
	EXPECT_EQ(EOPNOTSUPP, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}
