/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "tcp_base.h"

void tcp_base::SetUp()
{
	errno = EOK;
}

void tcp_base::TearDown()
{
}

int tcp_base::sock_create(bool reuse_addr)
{
	int rc;
	int fd;
	int opt_val = (reuse_addr ? 1 : 0);

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (fd < 0) {
		log_error("failed socket() %s\n", strerror(errno));
		return -1;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
	if (rc < 0) {
		log_error("failed setsockopt(SO_REUSEADDR) %s\n", strerror(errno));
		goto err;
	}

	return fd;

err:
	close(fd);

	return (-1);
}

int tcp_base::sock_create_nb(void)
{
	int rc;
	int fd;
	int opt_val = 0;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (fd < 0) {
		log_error("failed socket() %s\n", strerror(errno));
		goto err;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
	if (rc < 0) {
		log_error("failed setsockopt(SO_REUSEADDR) %s\n", strerror(errno));
		goto err;
	}

	rc = test_base::sock_noblock(fd);
	if (rc < 0) {
		log_error("failed sock_noblock() %s\n", strerror(errno));
		goto err;
	}

	return fd;

err:
	close(fd);

	return (-1);
}
