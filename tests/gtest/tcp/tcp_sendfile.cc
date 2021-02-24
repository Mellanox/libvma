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

#include <sys/mman.h>

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "tcp_base.h"

class tcp_sendfile : public tcp_base {
protected:
	void SetUp()
	{
		tcp_base::SetUp();

		errno = EOK;
		m_fd = -1;
		m_test_file = -1;
		m_test_file_size = 0;
		m_test_buf = NULL;
		m_test_buf_size = 0;
	}
	void TearDown()
	{
		if (m_test_buf) {
			free_tmp_buffer(m_test_buf, m_test_buf_size);
		}
		if (m_test_file >= 0) {
			close(m_test_file);
		}

		tcp_base::TearDown();
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
	void* create_tmp_buffer(size_t size) {
		char *ptr = NULL;
		size_t i = 0;

		ptr = (char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
		if (ptr != MAP_FAILED) {
			for (i = 0; i < size; i++) {
				ptr[i] = 'a' + (i % ('z' - 'a' + 1));
			}
		} else {
			ptr = NULL;
		}

		return ptr;
	}
	void free_tmp_buffer(void *ptr, size_t size) {
		munmap(ptr, size);
	}

protected:
	int m_fd;
	int m_test_file;
	int m_test_file_size;
	void *m_test_buf;
	int m_test_buf_size;
};


/**
 * @test tcp_sendfile.ti_1
 * @brief
 *    Exchange data by sendfile() single call
 *
 * @details
 */
TEST_F(tcp_sendfile, ti_1_basic) {
	int rc = EOK;
	void *file_ptr = NULL;

	m_test_file_size = 0x10000;
	m_test_file = create_tmp_file(m_test_file_size);
	ASSERT_GE(m_test_file, 0);

	m_test_buf_size = m_test_file_size;
	file_ptr = mmap(NULL, m_test_file_size, PROT_READ, MAP_SHARED | MAP_NORESERVE, m_test_file, 0);
	ASSERT_TRUE(file_ptr != MAP_FAILED);

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		off_t test_file_offset = 0;

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		while (m_test_file_size > 0) {
			rc = sendfile(m_fd, m_test_file, &test_file_offset, m_test_file_size);
			EXPECT_GE(rc, 0);
			m_test_file_size -= rc;
		}
		EXPECT_EQ(0, m_test_file_size);

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

		m_test_buf = (char *)create_tmp_buffer(m_test_buf_size);
		ASSERT_TRUE(m_test_buf);

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

		int i = m_test_buf_size;
		while (i > 0 && !child_fork_exit()) {
			rc = recv(m_fd, (void *)m_test_buf, i, MSG_WAITALL);
			EXPECT_GE(rc, 0);
			i -= rc;
		}
		EXPECT_EQ(0, i);
		EXPECT_EQ(memcmp(m_test_buf, file_ptr, m_test_buf_size), 0);

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}

	munmap(file_ptr, m_test_file_size);
}

/**
 * @test tcp_sendfile.ti_2
 * @brief
 *    Exchange data by sendfile() with different sizes
 *
 * @details
 */
TEST_F(tcp_sendfile, ti_2_vary_size) {
	int rc = EOK;
	struct {
		int chunk_size;
		int extra_size;
	} test_scenario [] = {
			{4096, 4096}, {4096, 0}, {4096, 1}, {4096, 2048}, {4096, 8192},
			{8192, 2048}, {8192, 4096}, {12288, 1024}, {12288, 2000}, {15360, 100},
			{15360, 300}, {1, 4096}, {2048, 4096}, {2048, 8192}, {1024, 12288},
			{2000, 12288}, {100, 15360}, {300, 15360}
	};
	int i = 0;

	for (i = 0; (i < (int)(sizeof(test_scenario) / sizeof(test_scenario[0]))); i++) {
		void *file_ptr = NULL;
		int test_chunk = test_scenario[i].chunk_size;
		int test_file_size = test_scenario[i].chunk_size + test_scenario[i].extra_size;
		int test_file = create_tmp_file(test_file_size);
		ASSERT_GE(test_file, 0);

		file_ptr = mmap(NULL, test_file_size, PROT_READ, MAP_SHARED | MAP_NORESERVE, test_file, 0);
		ASSERT_TRUE(file_ptr != MAP_FAILED);

		log_trace("Test case [%d]: chunk size: %d file size: %d\n",
				i, test_chunk, test_file_size);
		server_addr.sin_port = htons(gtest_conf.port + i);

		int pid = fork();
		if (0 == pid) {  /* I am the child */
			off_t test_file_offset = 0;

			barrier_fork(pid);

			m_fd = tcp_base::sock_create();
			ASSERT_LE(0, m_fd);

			rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
			ASSERT_EQ(0, rc);

			rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
			ASSERT_EQ(0, rc);

			log_trace("Established connection: fd=%d to %s\n",
					m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

			while (test_file_size > 0) {
				rc = sendfile(m_fd, test_file, &test_file_offset, test_file_size);
				EXPECT_GE(rc, 0);
				test_file_size -= rc;
			}
			EXPECT_EQ(0, test_file_size);

			peer_wait(m_fd);

			close(m_fd);
			close(test_file);

			/* This exit is very important, otherwise the fork
			 * keeps running and may duplicate other tests.
			 */
			exit(testing::Test::HasFailure());
		} else {  /* I am the parent */
			int l_fd;
			struct sockaddr peer_addr;
			socklen_t socklen;
			char *test_buf = NULL;

			test_buf = (char *)create_tmp_buffer(test_file_size);
			ASSERT_TRUE(test_buf);

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

			int s = test_file_size;
			while (s > 0 && !child_fork_exit()) {
				rc = recv(m_fd, (void *)test_buf, s, MSG_WAITALL);
				EXPECT_GE(rc, 0);
				s -= rc;
			}
			EXPECT_EQ(0, s);
			EXPECT_EQ(memcmp(test_buf, file_ptr, test_file_size), 0);

			close(m_fd);
			free_tmp_buffer(test_buf, test_file_size);
			test_buf = NULL;

			ASSERT_EQ(0, wait_fork(pid));
		}

		munmap(file_ptr, test_file_size);
	}
}
