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

#include "sock_base.h"

class sock_socket : public sock_base {};

/**
 * @test sock_socket.ti_1
 * @brief
 *    Create UDP socket
 * @details
 */
TEST_F(sock_socket, ti_1) {
	int fd = UNDEFINED_VALUE;

	errno = EOK;
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(EOK, errno);

	close(fd);
}

/**
 * @test sock_socket.ti_2
 * @brief
 *    Create TCP socket
 * @details
 */
TEST_F(sock_socket, ti_2) {
	int fd = UNDEFINED_VALUE;

	errno = EOK;
	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(EOK, errno);

	close(fd);
}

/**
 * @test sock_socket.ti_3
 * @brief
 *    Create UNIX socket
 * @details
 */
TEST_F(sock_socket, ti_3) {
	int fd = UNDEFINED_VALUE;

	errno = EOK;
	fd = socket(PF_UNIX, SOCK_DGRAM, IPPROTO_IP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(EOK, errno);

	close(fd);
}

/**
 * @test sock_socket.ti_4
 * @brief
 *    Create RAW socket
 * @details
 */
TEST_F(sock_socket, ti_4) {
	int fd = UNDEFINED_VALUE;

	errno = EOK;
	fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sys_rootuser()) {
		EXPECT_LE(0, fd);
		EXPECT_EQ(EOK, errno);
	} else {
		EXPECT_EQ(-1, fd);
		EXPECT_EQ(EPERM, errno);
	}

	close(fd);
}

/**
 * @test sock_socket.ti_5
 * @brief
 *    Check domain argument
 * @details
 */
TEST_F(sock_socket, ti_5) {
	int fd = UNDEFINED_VALUE;

	errno = EOK;
	fd = socket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_IP);
	EXPECT_EQ(-1, fd);
	EXPECT_EQ(EAFNOSUPPORT, errno);

	errno = EOK;
	fd = socket(PF_MAX + 1, SOCK_STREAM, IPPROTO_IP);
	EXPECT_EQ(-1, fd);
	EXPECT_EQ(EAFNOSUPPORT, errno);
}

/**
 * @test sock_socket.ti_6
 * @brief
 *    Check type argument
 * @details
 */
TEST_F(sock_socket, ti_6) {
	int fd = UNDEFINED_VALUE;

	errno = EOK;
	fd = socket(PF_INET, 0x10, IPPROTO_IP);
	EXPECT_EQ(-1, fd);
	EXPECT_EQ(EINVAL, errno);
}

/**
 * @test sock_socket.ti_7
 * @brief
 *    Check proto argument
 * @details
 */
TEST_F(sock_socket, ti_7) {
	int fd = UNDEFINED_VALUE;

	errno = EOK;
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(EOK, errno);

	close(fd);

	errno = EOK;
	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_UDP);
	EXPECT_EQ(-1, fd);
	EXPECT_EQ(EPROTONOSUPPORT, errno);

	close(fd);

	errno = EOK;
	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(EOK, errno);

	close(fd);

	errno = EOK;
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_TCP);
	EXPECT_EQ(-1, fd);
	EXPECT_EQ(EPROTONOSUPPORT, errno);

	close(fd);
}
