/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "tcp/tcp_base.h"
#include "udp/udp_base.h"
#include "vma_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

class vma_poll : public vma_base
{
protected:
	void SetUp()
	{
		vma_base::SetUp();

		SKIP_TRUE((getenv("VMA_SOCKETXTREME")), "This test requires VMA_SOCKETXTREME=1");
	}
	void TearDown()
	{
		vma_base::TearDown();
	}
};

/**
 * @test vma_poll.ti_1
 * @brief
 *    Check TCP connection acceptance (VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED)
 * @details
 */
TEST_F(vma_poll, ti_1) {
	int rc = EOK;
	int fd;

	errno = EOK;

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		struct epoll_event event;

		barrier_fork(pid);

		fd = tcp_base::sock_create_nb();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(EINPROGRESS, errno);
		ASSERT_EQ((-1), rc);

		event.events = EPOLLOUT | EPOLLIN;
		event.data.fd = fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_EQ((uint32_t)(EPOLLOUT), event.events);

		log_trace("Established connection: fd=%d to %s\n",
				fd, sys_addr2str((struct sockaddr_in *) &server_addr));

		close(fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int _vma_ring_fd = -1;
		struct vma_completion_t vma_comps;
		int fd_peer;
		struct sockaddr peer_addr;

		fd = tcp_base::sock_create_nb();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(fd, 5);
		ASSERT_EQ(EOK, errno);
		ASSERT_EQ(0, rc);

		rc = vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		ASSERT_EQ(1, rc);
		ASSERT_LE(0, _vma_ring_fd);

		barrier_fork(pid);
		rc = 0;
		while (rc == 0 && !child_fork_exit()) {
			rc = vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
			if (vma_comps.events & VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
				EXPECT_EQ(fd, (int)vma_comps.listen_fd);
				fd_peer = (int)vma_comps.user_data;
				EXPECT_LE(0, fd_peer);
				memcpy(&peer_addr, &vma_comps.src, sizeof(peer_addr));
				log_trace("Accepted connection: fd=%d from %s\n",
						fd_peer, sys_addr2str((struct sockaddr_in *)&peer_addr));
				rc = 0;
			}
		}

		close(fd_peer);
		close(fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test vma_poll.ti_2
 * @brief
 *    Check TCP connection data receiving (VMA_SOCKETXTREME_PACKET)
 * @details
 */
TEST_F(vma_poll, ti_2) {
	int rc = EOK;
	int fd;
	char msg[] = "Hello";

	errno = EOK;

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		barrier_fork(pid);

		fd = tcp_base::sock_create();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				fd, sys_addr2str((struct sockaddr_in *) &server_addr));

		rc = send(fd, (void *)msg, sizeof(msg), 0);
		EXPECT_EQ(sizeof(msg), rc);

		close(fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int _vma_ring_fd = -1;
		struct vma_completion_t vma_comps;
		int fd_peer;
		struct sockaddr peer_addr;

		fd = tcp_base::sock_create_nb();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(fd, 5);
		ASSERT_EQ(EOK, errno);
		ASSERT_EQ(0, rc);

		rc = vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		ASSERT_EQ(1, rc);
		ASSERT_LE(0, _vma_ring_fd);

		barrier_fork(pid);
		rc = 0;
		while (rc == 0 && !child_fork_exit()) {
			rc = vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
			if ((vma_comps.events & EPOLLERR) ||
					(vma_comps.events & EPOLLHUP) ||
					(vma_comps.events & EPOLLRDHUP)) {
				log_trace("Close connection: fd=%d event: 0x%lx\n", (int)vma_comps.user_data, vma_comps.events);
				rc = 0;
				break;
			}
			if (vma_comps.events & VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
				EXPECT_EQ(fd, (int)vma_comps.listen_fd);
				fd_peer = (int)vma_comps.user_data;
				EXPECT_LE(0, fd_peer);
				memcpy(&peer_addr, &vma_comps.src, sizeof(peer_addr));
				log_trace("Accepted connection: fd=%d from %s\n",
						fd_peer, sys_addr2str((struct sockaddr_in *)&peer_addr));
				rc = 0;
			}
			if (vma_comps.events & VMA_SOCKETXTREME_PACKET) {
				EXPECT_EQ(1, vma_comps.packet.num_bufs);
				EXPECT_LE(0, (int)vma_comps.user_data);
				EXPECT_EQ(sizeof(msg), vma_comps.packet.total_len);
				EXPECT_TRUE(vma_comps.packet.buff_lst->payload);
				log_trace("Received data: fd=%d data: %s\n",
						(int)vma_comps.user_data, (char *)vma_comps.packet.buff_lst->payload);
				rc = 0;
			}
		}

		close(fd_peer);
		close(fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}


/**
 * @test vma_poll.ti_3
 * @brief
 *    Check TCP connection data receiving (SO_VMA_USER_DATA)
 * @details
 */
TEST_F(vma_poll, ti_3) {
	int rc = EOK;
	int fd;
	char msg[] = "Hello";

	errno = EOK;

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		barrier_fork(pid);

		fd = tcp_base::sock_create();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				fd, sys_addr2str((struct sockaddr_in *) &server_addr));

		rc = send(fd, (void *)msg, sizeof(msg), 0);
		EXPECT_EQ(sizeof(msg), rc);

		close(fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int _vma_ring_fd = -1;
		struct vma_completion_t vma_comps;
		int fd_peer = -1;
		struct sockaddr peer_addr;
		const char *user_data = "This is a data";

		fd = tcp_base::sock_create_nb();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(fd, 5);
		ASSERT_EQ(EOK, errno);
		ASSERT_EQ(0, rc);

		rc = vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		ASSERT_EQ(1, rc);
		ASSERT_LE(0, _vma_ring_fd);

		barrier_fork(pid);
		rc = 0;
		while (rc == 0 && !child_fork_exit()) {
			rc = vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
			if ((vma_comps.events & EPOLLERR) ||
					(vma_comps.events & EPOLLHUP) ||
					(vma_comps.events & EPOLLRDHUP)) {
				log_trace("Close connection: event: 0x%lx\n", vma_comps.events);
				rc = 0;
				break;
			}
			if (vma_comps.events & VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
				EXPECT_EQ(fd, (int)vma_comps.listen_fd);
				fd_peer = (int)vma_comps.user_data;
				memcpy(&peer_addr, &vma_comps.src, sizeof(peer_addr));
				log_trace("Accepted connection: fd: %d from %s\n",
						fd_peer, sys_addr2str((struct sockaddr_in *)&peer_addr));

				errno = EOK;
				rc = setsockopt(fd_peer, SOL_SOCKET, SO_VMA_USER_DATA, &user_data, sizeof(void *));
				EXPECT_EQ(0, rc);
				EXPECT_EQ(EOK, errno);
				log_trace("Set data: %p\n", user_data);
				rc = 0;
			}
			if (vma_comps.events & VMA_SOCKETXTREME_PACKET) {
				EXPECT_EQ(1, vma_comps.packet.num_bufs);
				EXPECT_EQ((uintptr_t)user_data, (uintptr_t)vma_comps.user_data);
				EXPECT_EQ(sizeof(msg), vma_comps.packet.total_len);
				EXPECT_TRUE(vma_comps.packet.buff_lst->payload);
				log_trace("Received data: user_data: %p data: %s\n",
						(void *)((uintptr_t)vma_comps.user_data), (char *)vma_comps.packet.buff_lst->payload);
				rc = 0;
			}
		}

		close(fd_peer);
		close(fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test vma_poll.ti_4
 * @brief
 *    Check UDP connection data receiving (VMA_SOCKETXTREME_PACKET)
 * @details
 */
TEST_F(vma_poll, ti_4) {
	int rc = EOK;
	int fd;
	char msg[] = "Hello";

	errno = EOK;

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		barrier_fork(pid);

		fd = udp_base::sock_create();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = sendto(fd, (void *)msg, sizeof(msg), 0,
				(struct sockaddr *)&server_addr, sizeof(server_addr));
		EXPECT_EQ(sizeof(msg), rc);

		close(fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int _vma_ring_fd = -1;
		struct vma_completion_t vma_comps;
		int fd_peer = -1;

		fd = udp_base::sock_create_nb();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		ASSERT_EQ(1, rc);
		ASSERT_LE(0, _vma_ring_fd);

		barrier_fork(pid);
		rc = 0;
		while (rc == 0 && !child_fork_exit()) {
			rc = vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
			if ((vma_comps.events & EPOLLERR) ||
					(vma_comps.events & EPOLLHUP) ||
					(vma_comps.events & EPOLLRDHUP)) {
				log_trace("Close connection: fd=%d event: 0x%lx\n", (int)vma_comps.user_data, vma_comps.events);
				rc = 0;
				break;
			}
			if (vma_comps.events & VMA_SOCKETXTREME_PACKET) {
				EXPECT_EQ(1, vma_comps.packet.num_bufs);
				EXPECT_LE(0, (int)vma_comps.user_data);
				EXPECT_EQ(sizeof(msg), vma_comps.packet.total_len);
				EXPECT_TRUE(vma_comps.packet.buff_lst->payload);
				log_trace("Received data: fd=%d data: %s\n",
						(int)vma_comps.user_data, (char *)vma_comps.packet.buff_lst->payload);
				rc = 0;
			}
		}

		close(fd_peer);
		close(fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

#endif /* EXTRA_API_ENABLED */
