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

#include <time.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#ifdef SO_ZEROCOPY

#include "tcp_base.h"

class tcp_send_zc : public tcp_base {
protected:
	void SetUp() {
		int fd = -1;
		int rc = EOK;
		int opt_val = 1;

		tcp_base::SetUp();

		fd = tcp_base::sock_create();
		ASSERT_LE(0, fd);

		rc = setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		SKIP_TRUE((0 == rc), "TX zero copy is not supported");

		close(fd);

		errno = EOK;
		m_fd = -1;
		m_test_buf = NULL;
		m_test_buf_size = 0;
		m_test_buf_chunk = 0;
		m_test_file = -1;
	}
	void TearDown()	{
		if (m_test_buf) {
			free_tmp_buffer(m_test_buf, m_test_buf_size);
		}
		if (m_test_file >= 0) {
			close(m_test_file);
		}

		tcp_base::TearDown();
	}
	int do_recv_completion(int fd, uint32_t &lo, uint32_t &hi) {
		int ret = 0;
		struct sock_extended_err *serr;
		struct msghdr msg = {};
		struct cmsghdr *cmsg;
		uint32_t range;
		char cbuf[100];
		static uint32_t next_completion = 0;

		lo = hi = range = 0;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		ret = recvmsg(fd, &msg, MSG_ERRQUEUE);
		if (ret == -1 && errno == EAGAIN) {
			return 0;
		}
		if (ret == -1) {
			log_error("recvmsg notification failed errno: %d\n", errno);
		}
		if (msg.msg_flags & MSG_CTRUNC) {
			log_error("recvmsg notification: truncated errno: %d\n", errno);
		}

		cmsg = CMSG_FIRSTHDR(&msg);
		if (!cmsg) {
			log_error("no cmsg\n");
		}
		if (!((cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) ||
		      (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR) ||
		      (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_TX_TIMESTAMP))) {
			log_error("cmsg: wrong type: %d.%d\n",
					cmsg->cmsg_level, cmsg->cmsg_type);
		}

		serr = (sock_extended_err*)CMSG_DATA(cmsg);

		if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY) {
			log_error("serr: wrong origin: %u\n", serr->ee_origin);
		}
		if (serr->ee_errno != 0) {
			log_error("serr: wrong error code: %u\n", serr->ee_errno);
		}

		hi = serr->ee_data;
		lo = serr->ee_info;
		range = hi - lo + 1;

		/* Notification gaps due to drops,
		 * reordering and retransmissions.
		 */
		if (lo != next_completion) {
			log_trace("gap: %u..%u does not append to %u\n",
				lo, hi, next_completion);
		}
		next_completion = hi + 1;

		log_trace("completed as %s: %u (l=%u h=%u)\n",
				(serr->ee_code & SO_EE_CODE_ZEROCOPY_COPIED ? "copy" : "zero copy"), range, lo, hi);

		return range;
	}
	int do_recv_expected_completion(int fd, uint32_t &lo, uint32_t &hi, int expected) {
		int ret = 0;
		int wait_ms = 500;
		uint32_t _lo = 0;
		uint32_t _hi = 0;
		int completion = 0;

		lo = (uint32_t)(-1);
		hi = 0;
		while ((completion < expected) && (wait_ms--)) {
			ret = do_recv_completion(fd, _lo, _hi);
			if (ret > 0) {
				completion += ret;
				lo = sys_min(lo, _lo);
				hi = _hi;
			} else {
				usleep(1000);
			}
		}
		return completion;
	}
	int create_tmp_file(size_t size) {
		char filename[] = "/tmp/mytemp.XXXXXX";
		int fd = mkstemp(filename);

		if (fd >= 0) {
			unlink(filename);
			while (size--) {
				char buf = size % 255;
				write(fd, &buf, sizeof(buf));
			}
			fsync(fd);
		}
		return fd;
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
	int m_test_file;
	int m_test_buf_size;
	int m_test_buf_chunk;
};

/**
 * @test tcp_send_zc.ti_1
 * @brief
 *    Send data using single send(MSG_ZEROCOPY)
 * @details
 */
TEST_F(tcp_send_zc, ti_1_send_once) {
	int rc = EOK;
	char test_msg[] = "Hello test";

	m_test_buf = (char *)create_tmp_buffer(sizeof(test_msg), &m_test_buf_size);
	ASSERT_TRUE(m_test_buf);

	memcpy(m_test_buf, test_msg, sizeof(test_msg));

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		int opt_val = 1;
		uint32_t lo, hi;
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

		rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		rc = send(m_fd, (void *)m_test_buf, sizeof(test_msg), MSG_DONTWAIT | MSG_ZEROCOPY);
		EXPECT_EQ(sizeof(test_msg), rc);

		event.events = EPOLLOUT;
		event.data.fd = m_fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_TRUE(EPOLLOUT | event.events);

		rc = do_recv_expected_completion(m_fd, lo, hi, 1);
		EXPECT_EQ(1, rc);
		EXPECT_EQ(0, lo);
		EXPECT_EQ(0, hi);

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
		char buf[sizeof(test_msg)];

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

		rc = recv(m_fd, (void *)buf, sizeof(buf), 0);
		EXPECT_EQ(sizeof(test_msg), rc);

		log_trace("Test check: expected: '%s' actual: '%s'\n",
				test_msg, buf);

		EXPECT_EQ(memcmp(buf, m_test_buf, rc), 0);

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test tcp_send_zc.ti_2
 * @brief
 *    Send data using few sendmsg(MSG_ZEROCOPY)
 * @details
 */
TEST_F(tcp_send_zc, ti_2_few_send) {
	int rc = EOK;
	int test_iter = 3;
	int test_msg_size = 16;
	int i = 0;
	char *ptr = NULL;

	m_test_buf = (char *)create_tmp_buffer((test_iter * test_msg_size), &m_test_buf_size);
	ASSERT_TRUE(m_test_buf);

	ptr = m_test_buf;
	for (i = 0; i < test_iter; i++) {
		rc = snprintf(ptr, test_msg_size, "Hello test: #%2d", i);
		ptr += test_msg_size;
	}

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		int opt_val = 1;
		uint32_t lo, hi;
		struct epoll_event event;
		struct iovec vec[1];
		struct msghdr msg;

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		ptr = m_test_buf;
		for (i = 0; i < test_iter; i++) {
			vec[0].iov_base = (void *)ptr;
			vec[0].iov_len = test_msg_size;

			memset(&msg, 0, sizeof(struct msghdr));
			msg.msg_iov = vec;
			msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);
			rc = sendmsg(m_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
			EXPECT_EQ(test_msg_size, rc);

			ptr += test_msg_size;
		}

		event.events = EPOLLOUT;
		event.data.fd = m_fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_TRUE(EPOLLOUT | event.events);

		rc = do_recv_expected_completion(m_fd, lo, hi, test_iter);
		EXPECT_EQ(test_iter, rc);
		EXPECT_EQ(0, lo);
		EXPECT_EQ((test_iter - 1), hi);

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

		ptr = m_test_buf;
		for (i = 0; i < test_iter; i++) {
			char buf[test_msg_size];
			rc = recv(m_fd, (void *)buf, sizeof(buf), 0);
			EXPECT_EQ(test_msg_size, rc);

			log_trace("Test check #%d: expected: '%s' actual: '%s'\n",
					i, ptr, buf);

			EXPECT_EQ(memcmp(buf, ptr, rc), 0);

			ptr += test_msg_size;
		}

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test tcp_send_zc.ti_3
 * @brief
 *    Send large data using sendmsg(MSG_ZEROCOPY) as
 *    single call
 * @details
 */
TEST_F(tcp_send_zc, ti_3_large_send) {
	int rc = EOK;

	m_test_buf_chunk = 0x1000;
	m_test_buf_size = 10 * m_test_buf_chunk;

	m_test_buf = (char *)create_tmp_buffer(m_test_buf_size);
	ASSERT_TRUE(m_test_buf);
	ASSERT_TRUE(m_test_buf_chunk <= m_test_buf_size);

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		int opt_val = 1;
		uint32_t lo, hi;
		struct epoll_event event;
		struct iovec vec[(m_test_buf_size + (m_test_buf_chunk - 1)) / m_test_buf_chunk];
		struct msghdr msg;
		int i = 0;

		while ((i * m_test_buf_chunk) < m_test_buf_size) {
			vec[i].iov_base = (void *)((uintptr_t)m_test_buf + (i * m_test_buf_chunk));
			vec[i].iov_len = sys_min(m_test_buf_chunk, (m_test_buf_size - i * m_test_buf_chunk));
			i++;
		}

		memset(&msg, 0, sizeof(struct msghdr));
		msg.msg_iov = vec;
		msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);

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

		opt_val = 1;
		rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		rc = sendmsg(m_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
		EXPECT_EQ(m_test_buf_size, rc);

		event.events = EPOLLOUT;
		event.data.fd = m_fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_TRUE(EPOLLOUT | event.events);

		rc = do_recv_expected_completion(m_fd, lo, hi, 1);
		EXPECT_EQ(1, rc);
		EXPECT_EQ(0, lo);
		EXPECT_EQ(0, hi);

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
		int i = 0;
		char *buf = NULL;

		buf = (char *)malloc(m_test_buf_size);
		ASSERT_TRUE(buf);

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

		i = m_test_buf_size;
		while (i > 0 && !child_fork_exit()) {
			rc = recv(m_fd, (void *)buf, i, MSG_WAITALL);
			EXPECT_GE(rc, 0);
			i -= rc;
		}
		EXPECT_EQ(0, i);
		EXPECT_EQ(memcmp(buf, m_test_buf, m_test_buf_size), 0);

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test tcp_send_zc.ti_4
 * @brief
 *    Do sequence of send operations with different sizes
 *    using sendmsg(MSG_ZEROCOPY) and check completion
 *    notification after every call
 * @details
 */
TEST_F(tcp_send_zc, ti_4_mass_send_check_every_call) {
	int rc = EOK;
	struct {
		int num_op;
		int buf_size;
		int buf_chunk;
	} test_scenario [] = {
			{1, 4096, 4096}, {1, 40960, 4096}, {10, 40960, 4096}, {5, 4096, 2048}, {10, 4096, 512},
			{1, 8192, 2048}, {2, 8192, 4096}, {5, 12288, 1024}, {5, 12288, 2000}, {20, 1869, 200}
	};
	int i = 0;

	for (i = 0; (i < (int)(sizeof(test_scenario) / sizeof(test_scenario[0]))); i++) {
		int test_buf_size = test_scenario[i].buf_size;
		int test_buf_chunk = test_scenario[i].buf_chunk;
		int test_call = test_scenario[i].num_op;
		char *test_buf = (char *)create_tmp_buffer(test_buf_size);
		ASSERT_TRUE(test_buf);
		ASSERT_TRUE(test_buf_chunk <= test_buf_size);

		log_trace("Test case [%d]: iter: %d data size: %d chunk size: %d\n",
				i, test_call, test_buf_size, test_buf_chunk);
		server_addr.sin_port = htons(gtest_conf.port + i);

		int pid = fork();
		if (0 == pid) {  /* I am the child */
			int opt_val = 1;
			uint32_t lo, hi;
			struct epoll_event event;
			struct iovec vec[(test_buf_size + (test_buf_chunk - 1)) / test_buf_chunk];
			struct msghdr msg;
			int j = 0;

			while ((j * test_buf_chunk) < test_buf_size) {
				vec[j].iov_base = (void *)((uintptr_t)test_buf + (j * test_buf_chunk));
				vec[j].iov_len = sys_min(test_buf_chunk, (test_buf_size - j * test_buf_chunk));
				j++;
			}

			memset(&msg, 0, sizeof(struct msghdr));
			msg.msg_iov = vec;
			msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);

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

			opt_val = 1;
			rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
			ASSERT_EQ(0, rc);

			for (i = 0; (i < test_call) && (!child_fork_exit()); i++) {
				rc = sendmsg(m_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
				EXPECT_EQ(test_buf_size, rc);

				event.events = EPOLLOUT;
				event.data.fd = m_fd;
				rc = test_base::event_wait(&event);
				EXPECT_LT(0, rc);
				EXPECT_TRUE(EPOLLOUT | event.events);

				rc = do_recv_expected_completion(m_fd, lo, hi, 1);
				EXPECT_EQ(1, rc);
				EXPECT_EQ(i, lo);
				EXPECT_EQ(i, hi);
			}

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
			char *buf = NULL;

			buf = (char *)malloc(test_buf_size);
			ASSERT_TRUE(buf);

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

			for (i = 0; (i < test_call) && (!child_fork_exit()); i++) {
				int j = test_buf_size;
				while (j > 0 && !child_fork_exit()) {
					rc = recv(m_fd, (void *)buf, test_buf_size, MSG_WAITALL);
					EXPECT_GE(rc, 0);
					j -= rc;
				}
				EXPECT_EQ(0, j);
				EXPECT_EQ(memcmp(buf, test_buf, test_buf_size), 0);
			}

			close(m_fd);
			free(buf);
			free_tmp_buffer(test_buf, test_buf_size);
			test_buf = NULL;

			ASSERT_EQ(0, wait_fork(pid));
		}
	}
}

/**
 * @test tcp_send_zc.ti_5
 * @brief
 *    Do sequence of send operations with different sizes
 *    using sendmsg(MSG_ZEROCOPY) and check completion
 *    notification after last call
 * @details
 */
TEST_F(tcp_send_zc, ti_5_mass_send_check_last_call) {
	int rc = EOK;
	struct {
		int buf_size;
		int buf_chunk;
	} test_scenario [] = {
			{4096, 4096}, {40960, 4096}, {40960, 4096}, {4096, 2048}, {4096, 512},
			{8192, 2048}, {8192, 4096}, {12288, 1024}, {12288, 2000}, {1869, 200}
	};
	int i = 0;

	for (i = 0; (i < (int)(sizeof(test_scenario) / sizeof(test_scenario[0]))); i++) {
		int test_buf_size = test_scenario[i].buf_size;
		int test_buf_chunk = test_scenario[i].buf_chunk;
		int test_call = (test_buf_size + (test_buf_chunk - 1)) / test_buf_chunk;
		char *test_buf = (char *)create_tmp_buffer(test_buf_size);
		ASSERT_TRUE(test_buf);
		ASSERT_TRUE(test_buf_chunk <= test_buf_size);

		log_trace("Test case [%d]: op: %d data size: %d chunk size: %d\n",
				i, test_call, test_buf_size, test_buf_chunk);
		server_addr.sin_port = htons(gtest_conf.port + i);

		int pid = fork();
		if (0 == pid) {  /* I am the child */
			int opt_val = 1;
			uint32_t lo, hi;
			struct epoll_event event;
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

			opt_val = 1;
			rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
			ASSERT_EQ(0, rc);


			for (int j = 0; j < test_call; j++) {
				vec[0].iov_base = (void *)((uintptr_t)test_buf + (j * test_buf_chunk));
				vec[0].iov_len = sys_min(test_buf_chunk, (test_buf_size - j * test_buf_chunk));

				memset(&msg, 0, sizeof(struct msghdr));
				msg.msg_iov = vec;
				msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);
				rc = sendmsg(m_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
				EXPECT_EQ(vec[0].iov_len, rc);
			}

			event.events = EPOLLOUT;
			event.data.fd = m_fd;
			rc = test_base::event_wait(&event);
			EXPECT_LT(0, rc);
			EXPECT_TRUE(EPOLLOUT | event.events);

			rc = do_recv_expected_completion(m_fd, lo, hi, test_call);
			EXPECT_EQ(test_call, rc);
			EXPECT_EQ(0, lo);
			EXPECT_EQ((test_call - 1), hi);

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
			char *buf = NULL;

			buf = (char *)malloc(test_buf_size);
			ASSERT_TRUE(buf);

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

			int j = test_buf_size;
			while (j > 0 && !child_fork_exit()) {
				rc = recv(m_fd, (void *)buf, test_buf_size, MSG_WAITALL);
				EXPECT_GE(rc, 0);
				j -= rc;
			}
			EXPECT_EQ(0, j);
			EXPECT_EQ(memcmp(buf, test_buf, test_buf_size), 0);

			close(m_fd);
			free(buf);
			free_tmp_buffer(test_buf, test_buf_size);
			test_buf = NULL;

			ASSERT_EQ(0, wait_fork(pid));
		}
	}
}

#endif /* SO_ZEROCOPY */
