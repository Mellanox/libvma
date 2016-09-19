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

void vma_base::SetUp()
{
	errno = EOK;
	vma_api = vma_get_api();
	ASSERT_TRUE(vma_api) <<
			"vma test suite should be launched under libvma.so";
}

void vma_base::TearDown()
{
}

void vma_base::ec_wait(int fd, struct vma_completion_t *ec)
{
	int rc = 0;
	int rfd;
	double start_t = sys_gettime();
	double delta_t = 10 * 1E6; /* 10sec time limitation */

	rc = vma_api->get_socket_rings_fds(fd, &rfd, 1);
	EXPECT_EQ(EOK, errno);
	EXPECT_EQ(1, rc);
	ASSERT_LE(0, rfd);

	rc = 0;
	memset(ec, 0, sizeof(*ec));
	while (0 == rc) {
		rc = vma_api->vma_poll(rfd, ec, 1, 0);
		ASSERT_TRUE(rc >= 0);
		if (delta_t < (sys_gettime() - start_t)) {
			rc = -1;
		}
	}

	if (ec->packet.num_bufs > 0) {
		vma_api->free_vma_packets(&ec->packet, 1);
	}
	EXPECT_EQ(1, rc);
}
