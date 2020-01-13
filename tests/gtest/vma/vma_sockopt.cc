/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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

#include "vma_base.h"

#if defined(VMA_EXTRA_API_ENABLED) && (VMA_EXTRA_API_ENABLED == 1)

class vma_sockopt : public vma_base {};

/**
 * @test vma_sockopt.ti_1
 * @brief
 *    UDP RING_USER_ID good flow
 * @details
 */
TEST_F(vma_sockopt, ti_1) {
	int rc = EOK;
	int fd = UNDEFINED_VALUE;
	struct vma_ring_alloc_logic_attr profile;
	int user_id = 100;

	memset(&profile, 0, sizeof(struct vma_ring_alloc_logic_attr));

	profile.user_id = user_id;
	profile.ring_alloc_logic = RING_LOGIC_PER_USER_ID;
	profile.engress = 1;
	profile.comp_mask = VMA_RING_ALLOC_MASK_RING_USER_ID | VMA_RING_ALLOC_MASK_RING_ENGRESS;
	
	errno = EOK;
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(EOK, errno);

	errno = EOK;
	rc = setsockopt(fd, SOL_SOCKET, SO_VMA_RING_ALLOC_LOGIC, &profile, sizeof(profile));
	EXPECT_EQ(0, rc);
	EXPECT_EQ(EOK, errno);

	close(fd);
}

/**
 * @test vma_sockopt.ti_2
 * @brief
 *    UDP RING_USER_ID bad flow
 * @details
 */
TEST_F(vma_sockopt, ti_2) {
        int rc = EOK;
	int fd = UNDEFINED_VALUE;
	struct vma_ring_alloc_logic_attr profile;
	int user_id = 100;
	int unsupported_mask = (1<<4);

	memset(&profile, 0, sizeof(struct vma_ring_alloc_logic_attr));

	profile.user_id = user_id;
	profile.ring_alloc_logic = RING_LOGIC_PER_USER_ID;
	profile.engress = 1;
	profile.comp_mask = unsupported_mask;

	errno = EOK;
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	EXPECT_LE(0, fd);
	EXPECT_EQ(EOK, errno);

	/* Wrong passed value */
	errno = EOK;
	rc = setsockopt(fd, SOL_SOCKET, SO_VMA_RING_ALLOC_LOGIC, &profile, sizeof(profile));
	EXPECT_GT(0, rc);
	EXPECT_EQ(EINVAL, errno);

	/* Wrong data size */
	errno = EOK;
	rc = setsockopt(fd, SOL_SOCKET, SO_VMA_RING_ALLOC_LOGIC, &profile, sizeof(profile) - 1);
	EXPECT_GT(0, rc);
	EXPECT_EQ(EINVAL, errno);

	close(fd);
}

#endif /* VMA_EXTRA_API_ENABLED */
