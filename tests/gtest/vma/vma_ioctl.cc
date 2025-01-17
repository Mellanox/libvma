/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "common/cmn.h"

#include "tcp/tcp_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

#include "vma_base.h"

class vma_ioctl : public vma_base {
protected:
	void SetUp() {
		uint64_t vma_extra_api_cap = VMA_EXTRA_API_IOCTL;

		vma_base::SetUp();

		SKIP_TRUE((vma_api->vma_extra_supported_mask & vma_extra_api_cap) == vma_extra_api_cap,
				"This test requires VMA capabilities as VMA_EXTRA_API_IOCTL");
	}
	void TearDown()	{
		vma_base::TearDown();
	}
};

static size_t allocated_size = 0;
void *test_malloc(size_t size) {
	allocated_size += size;
	return malloc(size);
};

/**
 * @test vma_ioctl.ti_1
 * @note
 *    Should be launched individually (it depends on library init ordering)
 * @brief
 *    CMSG_XLIO_IOCTL_USER_ALLOC command message format check
 * @details
 */
TEST_F(vma_ioctl, ti_1) {
	int rc = EOK;
	int fd;
	vma_cmsg_ioctl_user_alloc_t data;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(data))];

	ASSERT_TRUE((sizeof(uint8_t) + sizeof(uintptr_t) + sizeof(uintptr_t)) == sizeof(data));

	/* scenario #1: Wrong cmsg length */
	errno = EOK;
	cmsg = (struct cmsghdr *)cbuf;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = CMSG_VMA_IOCTL_USER_ALLOC;
	cmsg->cmsg_len = CMSG_LEN(sizeof(data)) - 1;
	data.flags = VMA_IOCTL_USER_ALLOC_FLAG_RX;
	data.memalloc = malloc;
	data.memfree = free;
	memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

	rc = vma_api->ioctl(cmsg, cmsg->cmsg_len);
	EXPECT_EQ(-1, rc);
	EXPECT_TRUE(EINVAL == errno);

	/* scenario #2: invalid function pointer */
	errno = EOK;
	cmsg = (struct cmsghdr *)cbuf;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = CMSG_VMA_IOCTL_USER_ALLOC;
	cmsg->cmsg_len = CMSG_LEN(sizeof(data));
	data.flags = VMA_IOCTL_USER_ALLOC_FLAG_RX;
	data.memalloc = malloc;
	data.memfree = NULL;
	memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

	rc = vma_api->ioctl(cmsg, cmsg->cmsg_len);
	EXPECT_EQ(-1, rc);
	EXPECT_TRUE(EINVAL == errno);

	/* scenario #3: Check memory functions are activated */
	errno = EOK;
	cmsg = (struct cmsghdr *)cbuf;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = CMSG_VMA_IOCTL_USER_ALLOC;
	cmsg->cmsg_len = CMSG_LEN(sizeof(data));
	data.flags = VMA_IOCTL_USER_ALLOC_FLAG_RX;
	data.memalloc = &test_malloc;
	data.memfree = free;
	memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

	rc = vma_api->ioctl(cmsg, cmsg->cmsg_len);
	EXPECT_EQ(0, rc);

	/* the library initialization trigger */
	allocated_size = 0;
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	ASSERT_LE(0, fd);
	EXPECT_LT(1500, allocated_size);

	/* scenario #4: Command can not be used after initialization of internals */
	errno = EOK;
	cmsg = (struct cmsghdr *)cbuf;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = CMSG_VMA_IOCTL_USER_ALLOC;
	cmsg->cmsg_len = CMSG_LEN(sizeof(data));
	data.flags = VMA_IOCTL_USER_ALLOC_FLAG_TX | VMA_IOCTL_USER_ALLOC_FLAG_RX;
	data.memalloc = malloc;
	data.memfree = free;
	memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

	rc = vma_api->ioctl(cmsg, cmsg->cmsg_len);
	EXPECT_EQ(-1, rc);
	EXPECT_TRUE(EINVAL == errno);

	/* scenario #5: Successfull connection with customer memalloc */
	rc = EOK;
	char send_buf[] = "test";
	char recv_buf[sizeof(send_buf)];

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		barrier_fork(pid);

		fd = tcp_base::sock_create();
		ASSERT_LE(0, fd);

		rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		rc = send(fd, send_buf, sizeof(send_buf), 0);
		EXPECT_GE(rc, 0);

		close(fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int fd_peer;
		struct sockaddr peer_addr;
		socklen_t socklen;

		fd_peer = tcp_base::sock_create();
		ASSERT_LE(0, fd_peer);

		rc = bind(fd_peer, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(fd_peer, 5);
		ASSERT_EQ(0, rc);

		barrier_fork(pid);

		socklen = sizeof(peer_addr);
		fd = accept(fd_peer, &peer_addr, &socklen);
		ASSERT_LE(0, fd);

		log_trace("Accepted connection: fd=%d from %s\n",
				fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

		rc = recv(fd, (void *)recv_buf, sizeof(recv_buf), MSG_WAITALL);
		EXPECT_GE(rc, 0);
		EXPECT_EQ(memcmp(send_buf, recv_buf, sizeof(send_buf)), 0);

		close(fd_peer);
		close(fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

#endif /* EXTRA_API_ENABLED */
