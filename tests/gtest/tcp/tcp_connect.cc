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
#include <list>
#include <algorithm>
#include "tcp_base.h"

class tcp_connect : public tcp_base {};

/**
 * @test tcp_connect.ti_1
 * @brief
 *    Loop of blocking connect() to ip on the same node
 * @details
 */
TEST_F(tcp_connect, DISABLED_ti_1) {
	int rc = EOK;
	int fd;
	int i;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	for (i = 0; i < 10; i++) {
		rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_TRUE(ECONNREFUSED == errno) <<
				"connect() attempt = " << i;
		ASSERT_EQ((-1), rc) <<
				"connect() attempt = " << i;
		usleep(500);
	}

	close(fd);
}

/**
 * @test tcp_connect.ti_2
 * @brief
 *    Loop of blocking connect() to remote ip
 * @details
 */
TEST_F(tcp_connect, DISABLED_ti_2) {
	int rc = EOK;
	int fd;
	int i;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	for (i = 0; i < 10; i++) {
		rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
		ASSERT_TRUE(ECONNREFUSED == errno || ETIMEDOUT == errno) <<
				"connect() attempt = " << i;
		ASSERT_EQ((-1), rc) <<
				"connect() attempt = " << i;
		usleep(500);
		if (ETIMEDOUT == errno) {
			log_warn("Routing issue, consider another remote address instead of %s\n",
					sys_addr2str(&remote_addr));
			break;
		}
	}

	close(fd);
}

/**
 * @test tcp_connect.ti_3
 * @brief
 *    Loop of blocking connect() to unreachable ip
 * @details
 */
TEST_F(tcp_connect, DISABLED_ti_3) {
	int rc = EOK;
	int fd;
	int i;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_LE(0, fd);

	rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	for (i = 0; i < 10; i++) {
		rc = connect(fd, (struct sockaddr *)&bogus_addr, sizeof(bogus_addr));
		ASSERT_EQ(EHOSTUNREACH, errno) <<
				"connect() attempt = " << i;
		ASSERT_EQ((-1), rc) <<
				"connect() attempt = " << i;
		usleep(500);
	}

	close(fd);
}

/**
 * @test tcp_connect.ti_4_rto_racing
 * @brief
 *    Loop of blocking connect() to unreachable ip
 * @details
 */
TEST_F(tcp_connect, ti_4_rto_racing)
{
    int pid = fork();

    if (0 == pid) { /* I am the child */
        int lfd = tcp_base::sock_create(true);
        ASSERT_LE(0, lfd);

        int rc = bind(lfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(lfd, 1024);
        ASSERT_EQ(0, rc);

        barrier_fork(pid, true);

        int fd = accept(lfd, nullptr, nullptr);
        ASSERT_LE(0, fd);

        close(fd);
        close(lfd);

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        auto connect_fn = [](const sockaddr_in &server_addr_in, std::list<int> &fns,
                             int rts) -> int {
            int fd = tcp_base::sock_create();
            EXPECT_LE(0, fd);
            if (fd <= 0) {
                return fd;
            }

            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            EXPECT_EQ(0, rc);
            if (rc != 0) {
                close(fd);
                return -1;
            }

            log_trace("Connecting...\n");
            while (--rts >= 0) {
                log_trace("Connecting... %d\n", rts);
                rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr_in),
                             sizeof(server_addr_in));

                if (0 == rc) {
                    fns.push_back(fd);
                    log_trace("Connected %zu sockets.\n", fns.size());
                    return fd;
                }

                sleep(3);
            }

            close(fd);
            return -1;
        };

        std::list<int> fns;

        barrier_fork(pid, true);

        int retries = 2;
        while (connect_fn(server_addr, fns, 2) > 0 || --retries > 0)
            ;

        ASSERT_EQ(0, wait_fork(pid));

        std::for_each(std::begin(fns), std::end(fns), [](int fd) { EXPECT_EQ(0, close(fd)); });
    }
}

/**
 * @test tcp_connect.ti_5_multi_connect
 * @brief
 *    Multiple connect on the same socket
 * @details
 */
TEST_F(tcp_connect, ti_5_multi_connect)
{
    int fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    EXPECT_EQ(0, rc);
    if (rc != 0) {
        close(fd);
    }

    // Failing connect
    rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr), sizeof(server_addr));
    ASSERT_NE(0, rc);

    int pid = fork();

    if (0 == pid) { /* I am the child */
        rc = -1;
        int lfd = tcp_base::sock_create(true);
        if (lfd > 0) {
            rc = bind(lfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            if (rc != 0) {
                log_trace("Bind errno: %d\n", errno);
            } else {
                rc = listen(lfd, 1024);
                if (rc == 0) {
                    barrier_fork(pid, true);
                    fd = accept(lfd, nullptr, nullptr);
                    if (fd > 0) {
                        close(fd);
                    }
                } else {
                    log_trace("Listen errno: %d\n", errno);
                }
            }

            close(lfd);
        }

        if (rc != 0) {
            barrier_fork(pid, true);
        }

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        barrier_fork(pid, true);

        rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr), sizeof(server_addr));
        EXPECT_TRUE(0 == rc || errno == ECONNABORTED);
        if (rc != 0) {
            log_trace("Connected errno: %d\n", errno);
        }

        rc = close(fd);
        EXPECT_EQ(0, rc);

        // Get the child process out of the accept.
        rc = -1;
        fd = tcp_base::sock_create();
        if (fd > 0) {
            rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            EXPECT_EQ(0, rc);
            if (rc == 0) {
                rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr),
                             sizeof(server_addr));
                if (rc != 0) {
                    log_trace("Final connected errno: %d\n", errno);
                }
            }
            close(fd);
        }

        if (0 != rc) {
            kill(pid, SIGKILL);
        }

        wait_fork(pid);
    }
}
