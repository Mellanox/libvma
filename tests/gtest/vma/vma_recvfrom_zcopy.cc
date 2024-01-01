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

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

#include "tcp/tcp_base.h"
#include "vma_base.h"

class vma_tcp_recvfrom_zcopy : public vma_base, public tcp_base {
protected:
	void SetUp() {
		uint64_t vma_extra_api_cap = VMA_EXTRA_API_RECVFROM_ZCOPY | VMA_EXTRA_API_FREE_PACKETS;

		vma_base::SetUp();
		tcp_base::SetUp();

		SKIP_TRUE((vma_api->vma_extra_supported_mask & vma_extra_api_cap) == vma_extra_api_cap,
				"This test requires VMA capabilities as VMA_EXTRA_API_RECVFROM_ZCOPY | VMA_EXTRA_API_FREE_PACKETS");

		m_fd = -1;
		m_test_buf = NULL;
		m_test_buf_size = 0;
	}
	void TearDown()	{
		if (m_test_buf) {
			free_tmp_buffer(m_test_buf, m_test_buf_size);
		}

		tcp_base::TearDown();
		vma_base::TearDown();
	}
	void* create_tmp_buffer(size_t size, int *alloc_size = NULL) {
		char *ptr = NULL;
		int page_size = 0x200000;
		size_t i = 0;

		size = (size + page_size - 1) & (~(page_size - 1));
		ptr = (char *)memalign(page_size, size);
		if (ptr) {
			for (i = 0; i < size; i++) {
				ptr[i] = 'a' + (i % ('z' - 'a' + 1));
			}
			if (alloc_size) {
				*alloc_size = size;
			}
		} else {
			ptr = NULL;
		}

		return ptr;
	}
	void free_tmp_buffer(void *ptr, size_t size) {
		UNREFERENCED_PARAMETER(size);
		free(ptr);
	}

protected:
	int m_fd;
	char *m_test_buf;
	int m_test_buf_size;
};

/**
 * @test vma_tcp_recvfrom_zcopy.ti_1
 * @brief
 *    Check for passing small receive buffer
 * @details
 */
TEST_F(vma_tcp_recvfrom_zcopy, ti_1) {
	int rc = EOK;
	char test_msg[] = "Hello test";

	m_test_buf = (char *)create_tmp_buffer(sizeof(test_msg));
	ASSERT_TRUE(m_test_buf);
	m_test_buf_size = sizeof(test_msg);

	memcpy(m_test_buf, test_msg, sizeof(test_msg));

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		struct epoll_event event;

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		rc = send(m_fd, (void *)m_test_buf, m_test_buf_size, MSG_DONTWAIT);
		EXPECT_EQ(m_test_buf_size, rc);

		event.events = EPOLLOUT;
		event.data.fd = m_fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_TRUE(EPOLLOUT | event.events);

		peer_wait(m_fd);

		close(m_fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int l_fd;
		struct sockaddr peer_addr;
		socklen_t socklen;
		int flags = 0;
		size_t vma_header_size = sizeof(vma_packets_t) + sizeof(vma_packet_t) + sizeof(iovec);
		char buf[m_test_buf_size + vma_header_size];

		l_fd = tcp_base::sock_create();
		ASSERT_LE(0, l_fd);

		rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(l_fd, 5);
		ASSERT_EQ(0, rc);

		barrier_fork(pid);

		socklen = sizeof(peer_addr);
		m_fd = accept(l_fd, &peer_addr, &socklen);
		ASSERT_LE(0, m_fd);
		close(l_fd);

		log_trace("Accepted connection: fd=%d from %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

		rc = vma_api->recvfrom_zcopy(m_fd, (void *)buf, vma_header_size - 1, &flags, NULL, NULL);
		EXPECT_EQ(-1, rc);
		EXPECT_TRUE(ENOBUFS == errno);

		rc = vma_api->recvfrom_zcopy(m_fd, (void *)buf, vma_header_size, &flags, NULL, NULL);
		EXPECT_EQ(m_test_buf_size, rc);
		EXPECT_TRUE(flags & MSG_VMA_ZCOPY);

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test vma_tcp_recvfrom_zcopy.ti_2
 * @brief
 *    Exchange single buffer
 * @details
 */
TEST_F(vma_tcp_recvfrom_zcopy, ti_2_recv_once) {
	int rc = EOK;
	char test_msg[] = "Hello test";

	m_test_buf = (char *)create_tmp_buffer(sizeof(test_msg));
	ASSERT_TRUE(m_test_buf);
	m_test_buf_size = sizeof(test_msg);

	memcpy(m_test_buf, test_msg, sizeof(test_msg));

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		struct epoll_event event;

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		rc = send(m_fd, (void *)m_test_buf, m_test_buf_size, MSG_DONTWAIT);
		EXPECT_EQ(m_test_buf_size, rc);

		event.events = EPOLLOUT;
		event.data.fd = m_fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_TRUE(EPOLLOUT | event.events);

		peer_wait(m_fd);

		close(m_fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int l_fd;
		struct sockaddr peer_addr;
		socklen_t socklen;
		int flags = 0;
		char buf[m_test_buf_size + sizeof(vma_packets_t) + sizeof(vma_packet_t) + sizeof(iovec)];
		struct vma_packets_t *vma_packets;
		struct vma_packet_t *vma_packet;

		l_fd = tcp_base::sock_create();
		ASSERT_LE(0, l_fd);

		rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(l_fd, 5);
		ASSERT_EQ(0, rc);

		barrier_fork(pid);

		socklen = sizeof(peer_addr);
		m_fd = accept(l_fd, &peer_addr, &socklen);
		ASSERT_LE(0, m_fd);
		close(l_fd);

		log_trace("Accepted connection: fd=%d from %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

		rc = vma_api->recvfrom_zcopy(m_fd, (void *)buf, sizeof(buf), &flags, NULL, NULL);
		EXPECT_EQ(m_test_buf_size, rc);
		EXPECT_TRUE(flags & MSG_VMA_ZCOPY);
		vma_packets = (struct vma_packets_t *)buf;
		EXPECT_EQ(1, vma_packets->n_packet_num);
		vma_packet = (struct vma_packet_t *)(buf + sizeof(struct vma_packets_t));
		EXPECT_EQ(1, vma_packet->sz_iov);
		EXPECT_EQ(m_test_buf_size, vma_packet->iov[0].iov_len);

		log_trace("Test check: expected: '%s' actual: '%s'\n",
				m_test_buf, (char *)vma_packet->iov[0].iov_base);

		EXPECT_EQ(memcmp(vma_packet->iov[0].iov_base, m_test_buf, m_test_buf_size), 0);

		rc = vma_api->free_packets(m_fd, vma_packets->pkts, vma_packets->n_packet_num);
		EXPECT_EQ(0, rc);

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test vma_tcp_recvfrom_zcopy.ti_3
 * @brief
 *    Exchange large data
 * @details
 */
TEST_F(vma_tcp_recvfrom_zcopy, ti_3_large_data) {
	int rc = EOK;
	struct {
		int buf_size;
	} test_scenario [] = {
			{1024}, {8192}, {12288}, {4096}, {1869}, {40960}
	};
	int i = 0;

	for (i = 0; (i < (int)(sizeof(test_scenario) / sizeof(test_scenario[0]))); i++) {
		int test_buf_size = test_scenario[i].buf_size;
		char *test_buf = (char *)create_tmp_buffer(test_buf_size);
		ASSERT_TRUE(test_buf);

		log_trace("Test case [%d]: data size: %d\n",
				i, test_buf_size);
		server_addr.sin_port = htons(gtest_conf.port + i);

		int pid = fork();
		if (0 == pid) {  /* I am the child */
			int opt_val = 1;
			struct iovec vec[1];
			struct msghdr msg;

			barrier_fork(pid);

			m_fd = tcp_base::sock_create();
			ASSERT_LE(0, m_fd);

			opt_val = 1 << 21;
			rc = setsockopt(m_fd, SOL_SOCKET, SO_SNDBUF, &opt_val, sizeof(opt_val));
			ASSERT_EQ(0, rc);

			rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
			ASSERT_EQ(0, rc);

			rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
			ASSERT_EQ(0, rc);

			log_trace("Established connection: fd=%d to %s\n",
					m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

			vec[0].iov_base = (void *)test_buf;
			vec[0].iov_len = test_buf_size;

			memset(&msg, 0, sizeof(struct msghdr));
			msg.msg_iov = vec;
			msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);
			rc = sendmsg(m_fd, &msg, MSG_DONTWAIT);
			EXPECT_EQ(vec[0].iov_len, rc);

			sleep(1);
			peer_wait(m_fd);

			close(m_fd);

			/* This exit is very important, otherwise the fork
			 * keeps running and may duplicate other tests.
			 */
			exit(testing::Test::HasFailure());
		} else {  /* I am the parent */
			int l_fd;
			struct sockaddr peer_addr;
			socklen_t socklen;
			int flags = 0;
			char buf[1024];
			struct vma_packets_t *vma_packets;
			struct vma_packet_t *vma_packet;
			struct iovec *vec;
			int efd;
			struct epoll_event event;
			int total_len = 0;

			efd = epoll_create1(0);
			ASSERT_LE(0, efd);

			l_fd = tcp_base::sock_create();
			ASSERT_LE(0, l_fd);

			rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
			ASSERT_EQ(0, rc);

			rc = listen(l_fd, 5);
			ASSERT_EQ(0, rc);

			barrier_fork(pid);

			socklen = sizeof(peer_addr);
			m_fd = accept(l_fd, &peer_addr, &socklen);
			ASSERT_LE(0, m_fd);
			close(l_fd);

			log_trace("Accepted connection: fd=%d from %s\n",
					m_fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

			rc = test_base::sock_noblock(m_fd);
			ASSERT_EQ(0, rc);

			event.data.fd = m_fd;
			event.events = EPOLLIN | EPOLLET;
			epoll_ctl(efd, EPOLL_CTL_ADD, m_fd, &event);

			while (!child_fork_exit() && (total_len < test_buf_size)) {
				if (epoll_wait(efd, &event, 1, -1)) {
					if (event.events & EPOLLIN) {
						char *ptr = buf;
						int n = 0;
						int j = 0;
						int packet_len = 0;

						rc = vma_api->recvfrom_zcopy(m_fd, (void *)buf, sizeof(buf), &flags, NULL, NULL);
						EXPECT_LT(0, rc);
						EXPECT_TRUE(flags & MSG_VMA_ZCOPY);
						total_len += rc;
						vma_packets = (struct vma_packets_t *)ptr;
						for (n = 0; n < (int)vma_packets->n_packet_num; n++) {
							packet_len = 0;
							ptr += sizeof(struct vma_packets_t);
							vma_packet = (struct vma_packet_t *)ptr;
							ptr += sizeof(struct vma_packet_t);
							vec = (struct iovec *)ptr;
							for (j = 0; j < (int)vma_packet->sz_iov; j++) {
								packet_len += vec[j].iov_len;
							}
							log_trace("packet[%d]: packet_id=%p sz_iov=%ld len=%d\n",
									n, vma_packet->packet_id, vma_packet->sz_iov, packet_len);
						}

						rc = vma_api->free_packets(m_fd, vma_packets->pkts, vma_packets->n_packet_num);
						EXPECT_EQ(0, rc);
					}
				}
			}
			EXPECT_EQ(test_buf_size, total_len);

			close(m_fd);
			free_tmp_buffer(test_buf, test_buf_size);
			test_buf = NULL;

			ASSERT_EQ(0, wait_fork(pid));
		}
	}
}

#endif /* EXTRA_API_ENABLED */
