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
#include <string>
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "udp_base.h"


class udp_send : public udp_base {};

/**
 * @test udp_send.ti_1
 * @brief
 *    send() successful call
 * @details
 */
TEST_F(udp_send, ti_1) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

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

	errno = EOK;
	ssize_t rcz = send(fd, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(static_cast<ssize_t>(sizeof(buf)), rcz);

	close(fd);
}

/**
 * @test udp_send.ti_2
 * @brief
 *    send() invalid socket fd
 * @details
 */
TEST_F(udp_send, ti_2) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

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

	errno = EOK;
	rc = send(0xFF, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EBADF, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test udp_send.ti_3
 * @brief
 *    send() invalid buffer length (>65,507 bytes)
 * @details
 */
TEST_F(udp_send, ti_3) {
	int rc = EOK;
	int fd;
	char buf[65508] = "hello";

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

	errno = EOK;
	rc = send(fd, (void *)buf, 65507, 0);
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(65507, rc);

	errno = EOK;
	rc = send(fd, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EMSGSIZE, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test udp_send.ti_4
 * @brief
 *    send() invalid address length
 * @details
 */
TEST_F(udp_send, ti_4) {
	int rc = EOK;
	int fd;

	fd = udp_base::sock_create();
	ASSERT_LE(0, fd);

	errno = EOK;
	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(0, rc);

	errno = EOK;
	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr) - 1);
	EXPECT_EQ(EINVAL, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test udp_send.ti_5
 * @brief
 *    send() invalid flag set
 * @details
 */
TEST_F(udp_send, ti_5) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";

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

	errno = EOK;
	rc = send(fd, (void *)buf, sizeof(buf), 0x000000FF);
	EXPECT_EQ(EOPNOTSUPP, errno);
	EXPECT_EQ(-1, rc);

	close(fd);
}

/**
 * @test udp_send.ti_6
 * @brief
 *    send() to zero port
 * @details
 */
TEST_F(udp_send, ti_6) {
	int rc = EOK;
	int fd;
	char buf[] = "hello";
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

	errno = EOK;
	ssize_t rcz = send(fd, (void *)buf, sizeof(buf), 0);
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(static_cast<ssize_t>(sizeof(buf)), rcz);

	close(fd);
}

/**
 * @test udp_send.null_iov_elements
 * @brief
 *    Sending null iov elements.
 *
 * @details
 */
TEST_F(udp_send, null_iov_elements) {
	std::string buff1("abcd");
	std::string buff2("efgh");
	std::string buff3("ijkl");
	std::string buff4("mnop");

	int pid = fork();
	if (0 == pid) {  // Child
		barrier_fork(pid);

		int fd = udp_base::sock_create();
		EXPECT_LE_ERRNO(0, fd);
		if (0 <= fd) {
			iovec vec[4];
			vec[0].iov_base = nullptr;
			vec[0].iov_len = 0U;
			vec[1].iov_base = const_cast<std::string::value_type *>(buff1.data());
			vec[1].iov_len = buff1.size();
			vec[2].iov_base = nullptr;
			vec[2].iov_len = 0U;
			vec[3].iov_base = const_cast<std::string::value_type *>(buff2.data());
			vec[3].iov_len = buff2.size();

			msghdr msg;
			msg.msg_iov = vec;
			msg.msg_iovlen = sizeof(vec) / sizeof(iovec);
			msg.msg_name = &server_addr;
			msg.msg_namelen = sizeof(server_addr);
			msg.msg_control = nullptr;
			msg.msg_controllen = 0;

			ssize_t rcs = sendmsg(fd, &msg, 0);
			EXPECT_EQ_ERRNO(static_cast<ssize_t>(vec[1].iov_len + vec[3].iov_len), rcs);
			log_trace("Sent1: %zd.\n", rcs);

			vec[1].iov_base = const_cast<std::string::value_type *>(buff3.data());
			vec[1].iov_len = buff3.size();
			vec[3].iov_base = const_cast<std::string::value_type *>(buff4.data());
			vec[3].iov_len = buff4.size();

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

			vec[1].iov_len = 1000U;
			rcs = sendmsg(fd, &msg, 0);
			EXPECT_LE_ERRNO(rcs, -1);
			EXPECT_TRUE(14 == errno);
			log_trace("Sent5: %zd.\n", rcs);

			close(fd);
		}

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int fd = udp_base::sock_create();
		EXPECT_LE_ERRNO(0, fd);
		if (0 <= fd) {
			int rc = set_socket_rcv_timeout(fd, 5);
			EXPECT_EQ_ERRNO(0, rc);

			rc = bind(fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));
			EXPECT_EQ_ERRNO(0, rc);
			if (0 == rc) {
				barrier_fork(pid);

				char buff[32] = {0};
				size_t received = 0U;
				size_t recvsize = buff1.size() + buff2.size() + buff3.size() + buff4.size();
				while (received < recvsize) {
					rc = recv(fd, buff + received, sizeof(buff) - received, 0);
					if (rc < 0 && errno != EINTR) {
						break;
					}

					received += static_cast<size_t>(rc);
					log_trace("Received %zd\n", received);
				}

				log_trace("Received Final %zd\n", received);
				std::string result = buff1 + buff2 + buff3 + buff4;
				EXPECT_EQ(result, std::string(buff));

				rc = recv(fd, buff, sizeof(buff), 0);
				EXPECT_EQ_ERRNO(0, rc);
			}

			close(fd);
		}

		EXPECT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test udp_send.null_iov_elements_single_iov
 * @brief
 *    Sending null iov elements fragmented.
 *
 * @details
 */
TEST_F(udp_send, null_iov_elements_single_iov) {
	std::string buff3("efgh");
	char buff4[] = "Dummy Control";

	int pid = fork();
	if (0 == pid) {  // Child
		barrier_fork(pid);

		int fd = udp_base::sock_create();
		EXPECT_LE_ERRNO(0, fd);
		if (0 <= fd) {
			int rc = connect(fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));
			EXPECT_EQ_ERRNO(0, rc);

			iovec vec[1];
			vec[0].iov_base = const_cast<std::string::value_type *>(buff3.data());
			vec[0].iov_len = buff3.size();

			ssize_t rcs = writev(fd, vec, sizeof(vec) / sizeof(iovec));
			EXPECT_EQ_ERRNO(static_cast<ssize_t>(buff3.size()), rcs);

			vec[0].iov_base = nullptr;
			vec[0].iov_len = 0U;
			msghdr msg;
			msg.msg_iov = vec;
			msg.msg_iovlen = 1U;
			msg.msg_name = &server_addr;
			msg.msg_namelen = sizeof(server_addr);
			msg.msg_control = nullptr;
			msg.msg_controllen = 0;
			rcs = sendmsg(fd, &msg, 0); // Kernel writev doe not send empty packet.
			EXPECT_EQ_ERRNO(0U, rcs);

			msg.msg_control = buff4;
			msg.msg_controllen = sizeof(buff4);

			rcs = sendmsg(fd, &msg, 0); // Kernel writev doe not send empty packet.
			EXPECT_EQ_ERRNO(0U, rcs);

			close(fd);
		}

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int fd = udp_base::sock_create();
		EXPECT_LE_ERRNO(0, fd);
		if (0 <= fd) {
			int rc = set_socket_rcv_timeout(fd, 5);
			EXPECT_EQ_ERRNO(0, rc);

			rc = bind(fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));
			EXPECT_EQ_ERRNO(0, rc);
			if (0 == rc) {
				barrier_fork(pid);

				char buff[32];
				ssize_t rcz = recv(fd, buff, sizeof(buff), 0);
				EXPECT_EQ_ERRNO(static_cast<ssize_t>(buff3.size()), rcz);
				EXPECT_TRUE(0 == memcmp(buff, buff3.c_str(), buff3.size()));

				rc = recv(fd, buff, sizeof(buff), 0);
				EXPECT_EQ_ERRNO(0, rc);

				rc = recv(fd, buff, sizeof(buff), 0);
				EXPECT_EQ_ERRNO(0, rc);
			}

			close(fd);
		}

		EXPECT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test udp_send.null_iov_elements_too_big_msg
 * @brief
 *    Sending null iov elements with send size > 65507.
 *
 * @details
 */
TEST_F(udp_send, null_iov_elements_too_big_msg) {
	std::vector<char> vec_data(65508);
	std::vector<char> vec_data2(35000);

	int fd = udp_base::sock_create();
	EXPECT_LE_ERRNO(0, fd);
	if (0 <= fd) {
		iovec vec[2];
		vec[0].iov_base = vec_data.data();
		vec[0].iov_len = vec_data.size();

		msghdr msg;
		msg.msg_iov = vec;
		msg.msg_iovlen = 1U;
		msg.msg_name = &server_addr;
		msg.msg_namelen = sizeof(server_addr);
		msg.msg_control = nullptr;
		msg.msg_controllen = 0;
		ssize_t rcs = sendmsg(fd, &msg, 0);
		EXPECT_LE_ERRNO(rcs, -1);
		EXPECT_EQ(EMSGSIZE, errno);

		vec[0].iov_base = vec_data2.data();
		vec[0].iov_len = vec_data2.size();
		vec[1].iov_base = vec_data2.data();
		vec[1].iov_len = vec_data2.size();
		msg.msg_iovlen = 2U;

		rcs = sendmsg(fd, &msg, 0);
		EXPECT_LE_ERRNO(rcs, -1);
		EXPECT_EQ(EMSGSIZE, errno);

		close(fd);
	}
}

/**
 * @test udp_send.DISABLED_null_iov_elements_fragmented
 * @brief
 *    Sending null iov elements fragmented.
 *
 * @details
 */
TEST_F(udp_send, DISABLED_null_iov_elements_fragmented) {
	char buff1[8000] = {0};
	char buff2[8000] = {0};

	int pid = fork();
	if (0 == pid) {  // Child
		barrier_fork(pid);

		int fd = udp_base::sock_create();
		EXPECT_LE_ERRNO(0, fd);
		if (0 <= fd) {
			int rc = connect(fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));
			EXPECT_EQ_ERRNO(0, rc);

			iovec vec[4];
			vec[0].iov_base = nullptr;
			vec[0].iov_len = 0U;
			vec[1].iov_base = buff1;
			vec[1].iov_len = sizeof(buff1);
			vec[2].iov_base = nullptr;
			vec[2].iov_len = 0U;
			vec[3].iov_base = buff2;
			vec[3].iov_len = sizeof(buff2);

			ssize_t rcs = writev(fd, vec, sizeof(vec) / sizeof(iovec));
			EXPECT_EQ_ERRNO(static_cast<ssize_t>(sizeof(buff1) + sizeof(buff2)), rcs);

			rcs = writev(fd, vec + 1, 1U);
			EXPECT_EQ_ERRNO(static_cast<ssize_t>(sizeof(buff1)), rcs);

			close(fd);
		}

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int fd = udp_base::sock_create();
		EXPECT_LE_ERRNO(0, fd);
		if (0 <= fd) {
			int rc = set_socket_rcv_timeout(fd, 5);
			EXPECT_EQ_ERRNO(0, rc);

			rc = bind(fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr));
			EXPECT_EQ_ERRNO(0, rc);
			if (0 == rc) {
				barrier_fork(pid);

				size_t recvsize = sizeof(buff1) + sizeof(buff1) + sizeof(buff2);
				std::vector<char> vec(recvsize);
				size_t received = 0U;

				while (received < recvsize) {
					rc = recv(fd, vec.data() + received, vec.size(), 0);
					if (rc < 0 && errno != EINTR) {
						break;
					}

					received += static_cast<size_t>(rc);
					log_trace("Received %d\n", rc);
				}

				log_trace("Received Final %zd\n", received);
				const char *raw_buff = vec.data();
				EXPECT_TRUE(0 == memcmp(raw_buff, buff1, sizeof(buff1))); raw_buff += sizeof(buff1);
				EXPECT_TRUE(0 == memcmp(raw_buff, buff2, sizeof(buff2))); raw_buff += sizeof(buff2);
				EXPECT_TRUE(0 == memcmp(raw_buff, buff1, sizeof(buff1)));
			}

			close(fd);
		}

		EXPECT_EQ(0, wait_fork(pid));
	}
}
