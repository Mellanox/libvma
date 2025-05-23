/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "vma_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

class vma_ring : public vma_base
{
protected:
	void SetUp()
	{
		vma_base::SetUp();

		SKIP_TRUE((getenv("VMA_SOCKETXTREME")), "This test requires VMA_SOCKETXTREME=1");
	}
	void TearDown()
	{
	}
};

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
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_GE(0, rc);
	EXPECT_EQ(UNDEFINED_VALUE, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_8) {
	int rc = EOK;
	int ring_fd = UNDEFINED_VALUE;
	int fd;
	struct sockaddr_in addr;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	/*
	 * XXX This is workaround for the situation when the socket from ti_7
	 * is not destroyed in time and the following bind() fails due to
	 * "Address already in use" error.
	 */
	memcpy(&addr, &server_addr, sizeof(addr));
	addr.sin_port = htons(ntohs(addr.sin_port) + 1);

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	ASSERT_EQ(0, rc);

	rc = listen(fd, 5);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd);

	close(fd);
}

TEST_F(vma_ring, ti_9) {
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

TEST_F(vma_ring, ti_10) {
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

	errno = EOK;
	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)opt_val, opt_len);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd);

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

	log_trace("bind(): fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &server_addr), opt_val);

	rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_bind, 1);
	EXPECT_GE(0, rc);
	EXPECT_EQ(UNDEFINED_VALUE, ring_fd_bind);

	opt_val[0] = '\0';
	opt_len = sizeof(opt_val);
	ASSERT_TRUE(sys_addr2dev(&client_addr, opt_val, opt_len));

	log_trace("SO_BINDTODEVICE: fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &client_addr), opt_val);

	errno = EOK;
	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)opt_val, opt_len);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_bind_opt, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd_bind_opt);

	rc = test_base::sock_noblock(fd);
	ASSERT_EQ(0, rc);

	rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	ASSERT_EQ(EINPROGRESS, errno);
	ASSERT_EQ((-1), rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_connect, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd_connect);

	EXPECT_FALSE(ring_fd_bind == ring_fd_bind_opt);
	EXPECT_TRUE(ring_fd_bind_opt == ring_fd_connect);

	close(fd);
}

TEST_F(vma_ring, ti_12) {
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

	errno = EOK;
	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)opt_val, opt_len);
	ASSERT_EQ(0, rc);

	rc = vma_api->get_socket_rings_fds(fd, &ring_fd_bind_opt, 1);
	EXPECT_EQ(1, rc);
	EXPECT_LE(0, ring_fd_bind_opt);

	opt_val[0] = '\0';
	opt_len = sizeof(opt_val);
	ASSERT_TRUE(sys_addr2dev(&client_addr, opt_val, opt_len));

	log_trace("bind(): fd=%d as %s on %s\n",
			fd, sys_addr2str((struct sockaddr_in *) &client_addr), opt_val);

	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
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

	EXPECT_TRUE(ring_fd_bind == ring_fd_bind_opt);
	EXPECT_TRUE(ring_fd_bind == ring_fd_connect);

	close(fd);
}

#endif /* EXTRA_API_ENABLED */
