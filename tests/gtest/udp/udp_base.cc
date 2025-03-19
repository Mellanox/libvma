/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "udp_base.h"

void udp_base::SetUp()
{
	errno = EOK;
}

void udp_base::TearDown()
{
}

int udp_base::sock_create(void)
{
	int rc;
	int fd;
	int opt_val = 0;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0) {
		log_error("failed socket() %s\n", strerror(errno));
		goto err;
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

int udp_base::sock_create_nb(void)
{
	int rc;
	int fd;
	int opt_val = 0;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
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
