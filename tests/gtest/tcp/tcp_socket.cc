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

class tcp_socket : public tcp_base {};

/**
 * @test tcp_socket.ti_1
 * @brief
 *    Create TCP socket
 * @details
 */
TEST_F(tcp_socket, ti_1) {
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(errno, EOK);

	close(fd);
}
