/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
