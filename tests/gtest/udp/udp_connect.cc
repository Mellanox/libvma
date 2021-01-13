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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "udp_base.h"

class udp_connect : public udp_base {};

/**
 * @test udp_connect.ti_1
 * @brief
 *    Loop of blocking connect() to ip on the same node
 * @details
 */
TEST_F(udp_connect, ti_1) {
	int rc = EOK;
	int fd;
	int i;

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

	for (i = 0; i < 10; i++) {
		rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(EOK, errno) <<
				"connect() attempt = " << i << "\n" << close(fd);
		ASSERT_EQ(0, rc) <<
				"connect() attempt = " << i << "\n" << close(fd);
		usleep(500);
	}

	close(fd);
}

/**
 * @test udp_connect.ti_2
 * @brief
 *    Loop of blocking connect() to remote ip
 * @details
 */
TEST_F(udp_connect, ti_2) {
	int rc = EOK;
	int fd;
	int i;

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	for (i = 0; i < 10; i++) {
		rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
		ASSERT_EQ(EOK, errno) <<
				"connect() attempt = " << i << "\n" << close(fd);
		ASSERT_EQ(0, rc) <<
				"connect() attempt = " << i << "\n" << close(fd);
		usleep(500);
	}

	close(fd);
}

/**
 * @test udp_connect.ti_3
 * @brief
 *    Loop of blocking connect() to unreachable ip
 * @details
 */
TEST_F(udp_connect, ti_3) {
	int rc = EOK;
	int fd;
	int i;

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&bogus_addr, sizeof(bogus_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	for (i = 0; i < 10; i++) {
		rc = connect(fd, (struct sockaddr *)&bogus_addr, sizeof(bogus_addr));
		ASSERT_EQ(EOK, errno) <<
				"connect() attempt = " << i << "\n" << close(fd);
		ASSERT_EQ(0, rc) <<
				"connect() attempt = " << i << "\n" << close(fd);
		usleep(500);
	}

	close(fd);
}

/**
 * @test udp_connect.ti_4
 * @brief
 *    Loop of blocking connect() to zero port
 * @details
 */
TEST_F(udp_connect, ti_4) {
	int rc = EOK;
	int fd;
	struct sockaddr_in addr;

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	memcpy(&addr, &server_addr, sizeof(addr));
	addr.sin_port = 0;

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	close(fd);
}
