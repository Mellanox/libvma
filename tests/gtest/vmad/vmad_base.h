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

#ifndef TESTS_GTEST_VMAD_BASE_H_
#define TESTS_GTEST_VMAD_BASE_H_


/**
 * VMAD Base class for tests
 */
class vmad_base : public testing::Test, public test_base {
protected:
	virtual void SetUp();
	virtual void TearDown();

	int msg_init(pid_t pid);
	int msg_exit(pid_t pid);

protected:
	pid_t m_self_pid;
	pid_t m_vmad_pid;

	const char *m_base_name;

	/* socket used for communication with daemon */
	int m_sock_fd;

	/* file descriptor that is tracked by daemon */
	int m_pid_fd;

	/* unix socket name
	 * size should be less than sockaddr_un.sun_path
	 */
	char m_sock_file[100];

	/* name of pid file */
	char m_pid_file[100];

	/* server address */
	struct sockaddr_un m_server_addr;
};

#endif /* TESTS_GTEST_VMAD_BASE_H_ */
