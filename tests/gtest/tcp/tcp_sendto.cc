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
