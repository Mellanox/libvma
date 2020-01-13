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
#include "common/base.h"
#include "common/cmn.h"

#include "vma_base.h"

#if defined(VMA_EXTRA_API_ENABLED) && (VMA_EXTRA_API_ENABLED == 1)

class vma_ring : public vma_base {};

TEST_F(vma_ring, ti_1) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;

	rc = vma_api->get_socket_rings_fds(0, &ring_fd, 1);
	EXPECT_GE(0, rc);
	EXPECT_EQ(UNDEFINED_VALUE, ring_fd);
}

TEST_F(vma_ring, ti_2) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_GE(0, rc);
	EXPECT_EQ(UNDEFINED_VALUE, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_3) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_4) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_5) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = test_base::sock_noblock(fd);
	ASSERT_EQ(0, rc);

	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_6) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_GE(0, rc);
	EXPECT_EQ(UNDEFINED_VALUE, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_7) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_8) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = test_base::sock_noblock(fd);
	ASSERT_EQ(0, rc);

	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(EINPROGRESS, errno);
	ASSERT_EQ((-1), rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_9) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;
	char opt_val[100];
	socklen_t opt_len;

	SKIP_TRUE(sys_rootuser(), "This test requires root permission");

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	opt_val[0] = '\0';
	opt_len = sizeof(opt_val);
	ASSERT_TRUE(sys_addr2dev(&server_addr, opt_val, opt_len));
	log_trace("SO_BINDTODEVICE: fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &server_addr), opt_val);

	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)opt_val, opt_len);
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_GE(0, rc);
	EXPECT_EQ(UNDEFINED_VALUE, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_10) {
	int rc = EOK;
	int ring_fd_bind = UNDEFINED_VALUE;
	int ring_fd_bind_opt = UNDEFINED_VALUE;
	int ring_fd_connect = UNDEFINED_VALUE;
	int fd;
	char opt_val[100];
	socklen_t opt_len;

	SKIP_TRUE(sys_rootuser(), "This test requires root permission");

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	opt_val[0] = '\0';
	opt_len = sizeof(opt_val);
	ASSERT_TRUE(sys_addr2dev(&server_addr, opt_val, opt_len));

	log_trace("bind(): fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &server_addr), opt_val);

	rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_bind, 1);
	EXPECT_GE(1, rc);
	EXPECT_LE(0, ring_fd_bind);

	opt_val[0] = '\0';
	opt_len = sizeof(opt_val);
	ASSERT_TRUE(sys_addr2dev(&client_addr, opt_val, opt_len));

	log_trace("SO_BINDTODEVICE: fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &client_addr), opt_val);

	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)opt_val, opt_len);
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_bind_opt, 1);
	EXPECT_GE(1, rc);
	EXPECT_LE(0, ring_fd_bind_opt);

	rc = test_base::sock_noblock(fd);
	ASSERT_EQ(0, rc);

	rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	ASSERT_EQ(EINPROGRESS, errno);
	ASSERT_EQ((-1), rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_connect, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd_connect);

	EXPECT_TRUE(ring_fd_bind == ring_fd_bind_opt);
	EXPECT_TRUE(ring_fd_bind == ring_fd_connect);

	close(fd);
}

TEST_F(vma_ring, ti_11) {
	int rc = EOK;
	int ring_fd_bind = UNDEFINED_VALUE;
	int ring_fd_bind_opt = UNDEFINED_VALUE;
	int ring_fd_connect = UNDEFINED_VALUE;
	int fd;
	char opt_val[100];
	socklen_t opt_len;

	SKIP_TRUE(sys_rootuser(), "This test requires root permission");

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	opt_val[0] = '\0';
	opt_len = sizeof(opt_val);
	ASSERT_TRUE(sys_addr2dev(&server_addr, opt_val, opt_len));

	log_trace("SO_BINDTODEVICE: fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &server_addr), opt_val);

	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)opt_val, opt_len);
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_bind_opt, 1);
	EXPECT_GE(0, rc);
	EXPECT_EQ(UNDEFINED_VALUE, ring_fd_bind_opt);

	opt_val[0] = '\0';
	opt_len = sizeof(opt_val);
	ASSERT_TRUE(sys_addr2dev(&client_addr, opt_val, opt_len));

	log_trace("bind(): fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &client_addr), opt_val);

	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_bind, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd_bind);

	rc = test_base::sock_noblock(fd);
	ASSERT_EQ(0, rc);

	rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	ASSERT_EQ(EINPROGRESS, errno);
	ASSERT_EQ((-1), rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_connect, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd_connect);

	EXPECT_TRUE(ring_fd_bind != ring_fd_bind_opt);
	EXPECT_TRUE(ring_fd_bind == ring_fd_connect);

	close(fd);
}

#endif /* VMA_EXTRA_API_ENABLED */
