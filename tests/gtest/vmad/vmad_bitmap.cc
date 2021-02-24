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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "vmad_base.h"

#include "tools/daemon/bitmap.h"

class vmad_bitmap : public ::testing::Test {};

TEST_F(vmad_bitmap, ti_1) {
	ASSERT_EQ(4, sizeof(bitmap_item_t));
}

TEST_F(vmad_bitmap, ti_2) {
	bitmap_t *bm = NULL;

	bitmap_create(&bm, 10);
	ASSERT_TRUE(bm);
	ASSERT_EQ(10, bitmap_size(bm));

	bitmap_destroy(bm);
}

TEST_F(vmad_bitmap, ti_3) {
	bitmap_t *bm = NULL;

	bitmap_create(&bm, 0x7ff);
	ASSERT_TRUE(bm);

	ASSERT_EQ(0x7ff, bitmap_size(bm));

	EXPECT_EQ(0, elem_idx(0));
	EXPECT_EQ(0, elem_idx(31));
	EXPECT_EQ(1, elem_idx(32));
	EXPECT_EQ(2, elem_idx(64));
	EXPECT_EQ(32, elem_idx(0x400));
	EXPECT_EQ(63, elem_idx(0x7ff));

	bitmap_destroy(bm);
}

TEST_F(vmad_bitmap, ti_4) {
	bitmap_t *bm = NULL;
	int bits[] = {0, 7, 31, 32, 64};
	size_t i;

	bitmap_create(&bm, 64);
	ASSERT_TRUE(bm);

	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		EXPECT_EQ(0, bitmap_test(bm, i));
		bitmap_set(bm, i);
		EXPECT_EQ(1, bitmap_test(bm, i));
	}

	bitmap_destroy(bm);
}

TEST_F(vmad_bitmap, ti_5) {
	bitmap_t *bm = NULL;
	int bits[] = {0, 7, 31, 32, 64};
	size_t i;

	bitmap_create(&bm, 64);
	ASSERT_TRUE(bm);

	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		EXPECT_EQ(0, bitmap_test(bm, i));
		bitmap_set(bm, i);
		EXPECT_EQ(1, bitmap_test(bm, i));
		bitmap_clear(bm, i);
		EXPECT_EQ(0, bitmap_test(bm, i));
	}

	bitmap_destroy(bm);
}

TEST_F(vmad_bitmap, ti_6) {
	bitmap_t *bm = NULL;
	int bits[] = {0, 7, 31, 32, 64};
	size_t i;

	bitmap_create(&bm, 64);
	ASSERT_TRUE(bm);

	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		EXPECT_EQ(0, bitmap_test(bm, i));
		bitmap_flip(bm, i);
		EXPECT_EQ(1, bitmap_test(bm, i));
	}

	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		EXPECT_EQ(1, bitmap_test(bm, i));
		bitmap_flip(bm, i);
		EXPECT_EQ(0, bitmap_test(bm, i));
	}

	bitmap_destroy(bm);
}

TEST_F(vmad_bitmap, ti_7) {
	bitmap_t *bm = NULL;

	bitmap_create(&bm, 64);
	ASSERT_TRUE(bm);

	ASSERT_EQ(64, bitmap_size(bm));

	EXPECT_EQ(0, bitmap_test_group(bm, 0, 7));
	EXPECT_EQ(0, bitmap_test_group(bm, 0, 64));

	bitmap_set(bm, 7);
	bitmap_set(bm, 8);
	EXPECT_EQ(1, bitmap_test_group(bm, 7, 2));

	EXPECT_EQ(-1, bitmap_test_group(bm, 6, 3));
	EXPECT_EQ(-1, bitmap_test_group(bm, 0, 64));

	bitmap_destroy(bm);
}

TEST_F(vmad_bitmap, ti_8) {
	bitmap_t *bm = NULL;

	bitmap_create(&bm, 64);
	ASSERT_TRUE(bm);

	ASSERT_EQ(64, bitmap_size(bm));

	EXPECT_EQ(0, bitmap_find_group(bm, 0, 2, 0));
	EXPECT_EQ(32, bitmap_find_group(bm, 32, 7, 0));

	EXPECT_EQ(-1, bitmap_find_group(bm, 0, 7, 1));
	EXPECT_EQ(-1, bitmap_find_group(bm, 32, 7, 1));

	bitmap_set(bm, 7);
	bitmap_set(bm, 8);
	EXPECT_EQ(7, bitmap_find_group(bm, 0, 2, 1));

	bitmap_destroy(bm);
}

TEST_F(vmad_bitmap, ti_9) {
	bitmap_t *bm = NULL;
	int i;

	bitmap_create(&bm, 64);
	ASSERT_TRUE(bm);

	ASSERT_EQ(64, bitmap_size(bm));

	EXPECT_EQ(0, bitmap_find_first_zero(bm));

	bitmap_set(bm, 0);
	bitmap_set(bm, 1);
	bitmap_set(bm, 2);
	EXPECT_EQ(3, bitmap_find_first_zero(bm));

	bitmap_set(bm, 4);
	EXPECT_EQ(3, bitmap_find_first_zero(bm));

	bitmap_set(bm, 3);
	EXPECT_EQ(5, bitmap_find_first_zero(bm));

	for (i = 0; i < 33; i++) {
		bitmap_set(bm, i);
	}
	EXPECT_EQ(33, bitmap_find_first_zero(bm));

	for (i = 0; i < 64; i++) {
		bitmap_set(bm, i);
	}
	EXPECT_EQ(-1, bitmap_find_first_zero(bm));

	bitmap_destroy(bm);
}
