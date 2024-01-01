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
#include <sys/uio.h>
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "tcp_base.h"

class tcp_send : public tcp_base {};

/**
 * @test tcp_send.ti_1
 * @brief
 *    send() invalid socket fd
 * @details
 */
TEST_F(tcp_send, ti_1) {
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
	rc = send(0xFF, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EBADF, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test tcp_send.ti_2
 * @brief
 *    send() no connection
 * @details
 */
TEST_F(tcp_send, ti_2) {
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
	rc = send(fd, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EPIPE, errno);
	EXPECT_EQ(-1, rc);
	(void)signal(SIGPIPE, SIG_DFL);

	close(fd);
}

/**
 * @test tcp_send.null_iov_elements
 * @brief
 *    Sending null iov elements.
 *
 * @details
 */
TEST_F(tcp_send, null_iov_elements) {
	std::string buff1("abcd");
	std::string buff2("efgh");
	std::string buff3("ijkl");
	std::string buff4("mnop");
	char buff5[] = "Dummy Control";

	int pid = fork();
	if (0 == pid) {  // Child
		barrier_fork(pid);

		int fd = tcp_base::sock_create();
		EXPECT_LE_ERRNO(0, fd);
		if (0 <= fd) {
			int rc = set_socket_rcv_timeout(fd, 5);
			EXPECT_EQ_ERRNO(0, rc);

			log_trace("Establishing connection: fd=%d to %s from %s\n", fd,
					  sys_addr2str(&server_addr), sys_addr2str(&client_addr));

			rc = bind(fd, reinterpret_cast<sockaddr *>(&client_addr), sizeof(client_addr));
			EXPECT_EQ_ERRNO(0, rc);
			if (0 == rc) {
				rc = connect(fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));
				EXPECT_EQ_ERRNO(0, rc);
				if (0 == rc) {
					log_trace("Established connection.\n");

					iovec vec[4];
					vec[0].iov_base = nullptr;
					vec[0].iov_len = 0U;
					vec[1].iov_base = const_cast<std::string::value_type *>(buff1.data());
					vec[1].iov_len = buff1.size();
					vec[2].iov_base = nullptr;
					vec[2].iov_len = 0U;
					vec[3].iov_base = const_cast<std::string::value_type *>(buff2.data());
					vec[3].iov_len = buff2.size();

					ssize_t rcs = writev(fd, vec, sizeof(vec) / sizeof(iovec));
					EXPECT_EQ_ERRNO(static_cast<ssize_t>(vec[1].iov_len + vec[3].iov_len), rcs);
					log_trace("Sent1: %zd.\n", rcs);

					vec[1].iov_base = const_cast<std::string::value_type *>(buff3.data());
					vec[1].iov_len = buff3.size();
					vec[3].iov_base = const_cast<std::string::value_type *>(buff4.data());
					vec[3].iov_len = buff4.size();

					msghdr msg;
					msg.msg_iov = vec;
					msg.msg_iovlen = sizeof(vec) / sizeof(iovec);
					msg.msg_name = nullptr;
					msg.msg_namelen = 0U;
					msg.msg_control = nullptr;
					msg.msg_controllen = 0;
					rcs = sendmsg(fd, &msg, 0);
					EXPECT_EQ_ERRNO(static_cast<ssize_t>(vec[1].iov_len + vec[3].iov_len), rcs);
					log_trace("Sent2: %zd.\n", rcs);

					vec[1].iov_len = 0U;
					vec[3].iov_base = nullptr;
					vec[3].iov_len = 0U;
					rcs = sendmsg(fd, &msg, 0);
					EXPECT_EQ_ERRNO(0U, rcs);
					log_trace("Sent3: %zd.\n", rcs);

					vec[1].iov_base = nullptr;
					rcs = sendmsg(fd, &msg, 0);
					EXPECT_EQ_ERRNO(0U, rcs);
					log_trace("Sent4: %zd.\n", rcs);

					vec[0].iov_base = nullptr;
					vec[0].iov_len = 0U;
					msg.msg_iovlen = 1U;
					msg.msg_control = buff5;
					msg.msg_controllen = sizeof(buff5);
					rcs = sendmsg(fd, &msg, 0);

					// Kernel checks access for every iov memory address and in this case returns errno=14.
					// VMA can handle this situation and just igonre this element and saving CPU cycles.
					vec[1].iov_len = 1000U;
					rcs = sendmsg(fd, &msg, 0);
					EXPECT_LE_ERRNO(rcs, 0);
					EXPECT_TRUE(rcs == 0 || 14 == errno);
					log_trace("Sent5: %zd.\n", rcs);

					peer_wait(fd);
				}
			}

			close(fd);
		}

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int l_fd = tcp_base::sock_create();
		EXPECT_LE_ERRNO(0, l_fd);
		if (0 <= l_fd) {
			int rc = set_socket_rcv_timeout(l_fd, 5);
			EXPECT_EQ_ERRNO(0, rc);

			rc = bind(l_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));
			EXPECT_EQ_ERRNO(0, rc);
			if (0 == rc) {
				rc = listen(l_fd, 5);
				EXPECT_EQ_ERRNO(0, rc);
				if (0 == rc) {
					barrier_fork(pid);

					int fd = accept(l_fd, nullptr, 0U);
					EXPECT_LE_ERRNO(0, fd);
					if (0 <= fd) {
						log_trace("Accepted connection: fd=%d\n", fd);

						char buff[32] = {0};
						size_t received = 0U;
						size_t recvsize = buff1.size() + buff2.size() + buff3.size() + buff4.size();
						while (received < recvsize) {
							rc = recv(fd, buff + received, sizeof(buff) - received, 0);
							if (0 == rc || (rc < 0 && errno != EINTR)) {
								break;
							}

							received += static_cast<size_t>(rc);
							log_trace("Received %zd\n", received);
						}

						log_trace("Received Final %zd\n", received);
						std::string result = buff1 + buff2 + buff3 + buff4;
						EXPECT_EQ(result, std::string(buff));

						close(fd);
					}
				}
			}

			close(l_fd);
		}

		EXPECT_EQ(0, wait_fork(pid));
	}
}
