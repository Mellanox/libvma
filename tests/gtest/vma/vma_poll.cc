/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd. All rights reserved.
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

#include "vma_base.h"

class vma_poll : public vma_base {};

TEST_F(vma_poll, ti_1) {
	int rc = EOK;
	int fd;
	struct vma_completion_t ec;

	fd = test_base::sock_create_nb(SOCK_STREAM);
	ASSERT_LE(0, fd);

	rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	ASSERT_EQ(EINPROGRESS, errno);
	ASSERT_EQ((-1), rc);

	vma_base::ec_wait(fd, &ec);
	EXPECT_EQ(EPOLLHUP | EPOLLIN, ec.events);

	close(fd);
}

TEST_F(vma_poll, ti_2) {
	int rc = EOK;
	int fd;
	struct vma_completion_t ec;

	fd = test_base::sock_create_nb(SOCK_STREAM);
	ASSERT_LE(0, fd);

	rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	ASSERT_EQ(EINPROGRESS, errno);
	ASSERT_EQ((-1), rc);

	vma_base::ec_wait(fd, &ec);
	EXPECT_EQ((EPOLLERR | EPOLLHUP | EPOLLIN), ec.events);

	close(fd);
}
