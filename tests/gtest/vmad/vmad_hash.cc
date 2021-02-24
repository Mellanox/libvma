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

#include "tools/daemon/hash.h"

struct element {
	hash_key_t key;
	int value;
};

class vmad_hash : public ::testing::Test {};

TEST_F(vmad_hash, ti_1) {
	hash_t ht;
	int reference[] = {3, 5, 107, 199};
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(reference); i++) {
		ht = hash_create(NULL, reference[i]);
		ASSERT_TRUE(ht);
		EXPECT_EQ(reference[i], hash_size(ht));
		EXPECT_EQ(0, hash_count(ht));
		hash_destroy(ht);
	}
}

TEST_F(vmad_hash, ti_2) {
	hash_t ht;
	int reference[] = {4, 12, 100, 200};
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(reference); i++) {
		ht = hash_create(NULL, reference[i]);
		ASSERT_FALSE(ht);
	}
}

TEST_F(vmad_hash, ti_3) {
	hash_t ht;
	struct element element[] = {{12345, 1}, {(hash_key_t)-12345, 2}, {0, 3}};
	size_t i;

	ht = hash_create(NULL, 5);
	ASSERT_TRUE(ht);
	ASSERT_EQ(5, hash_size(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		EXPECT_TRUE(hash_put(ht, element[i].key, &element[i]));
	}
	EXPECT_EQ(3, hash_count(ht));

	hash_destroy(ht);
}

TEST_F(vmad_hash, ti_4) {
	hash_t ht;
	struct element element[] = {{12345, 1}, {123, 2}, {12, 3}};
	size_t i;

	ht = hash_create(NULL, 5);
	ASSERT_TRUE(ht);
	ASSERT_EQ(5, hash_size(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		EXPECT_TRUE(hash_put(ht, element[i].key, &element[i]));
	}
	EXPECT_EQ(3, hash_count(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		EXPECT_EQ(((uintptr_t)&element[i]), ((uintptr_t)hash_get(ht, element[i].key)));
	}

	hash_destroy(ht);
}

TEST_F(vmad_hash, ti_5) {
	hash_t ht;
	struct element element[] = {{12345, 1}, {0, 2}, {12, 3}, {77, 4}};
	size_t i;

	ht = hash_create(NULL, 3);
	ASSERT_TRUE(ht);
	ASSERT_EQ(3, hash_size(ht));

	for (i = 0; i < ARRAY_SIZE(element) - 1; i++) {
		EXPECT_TRUE(hash_put(ht, element[i].key, &element[i]));
	}
	EXPECT_EQ(3, hash_count(ht));

	EXPECT_FALSE(hash_put(ht, element[3].key, &element[3]));
	EXPECT_EQ(3, hash_count(ht));

	hash_destroy(ht);
}

TEST_F(vmad_hash, ti_6) {
	hash_t ht;
	struct element element[] = {{12345, 1}, {0, 2}, {12, 3}};
	struct element *e;
	size_t i;

	ht = hash_create(NULL, 5);
	ASSERT_TRUE(ht);
	ASSERT_EQ(5, hash_size(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		EXPECT_TRUE(hash_put(ht, element[i].key, &element[i]));
	}
	EXPECT_EQ(3, hash_count(ht));

	element[1].value = 555;
	e = (struct element *)hash_get(ht, element[1].key);
	EXPECT_EQ(((uintptr_t)&element[1]), ((uintptr_t)e));
	EXPECT_EQ(3, hash_count(ht));
	e = (struct element *)hash_get(ht, element[1].key);
	ASSERT_TRUE(e);
	EXPECT_EQ(((uintptr_t)&element[1]), ((uintptr_t)e));
	EXPECT_EQ(555, e->value);

	hash_destroy(ht);
}

TEST_F(vmad_hash, ti_7) {
	hash_t ht;
	struct element element[] = {{12345, 1}, {123, 2}, {1234, 3}};
	size_t i;

	ht = hash_create(NULL, 5);
	ASSERT_TRUE(ht);
	ASSERT_EQ(5, hash_size(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		EXPECT_TRUE(hash_put(ht, element[i].key, &element[i]));
	}
	EXPECT_EQ(3, hash_count(ht));

	hash_del(ht, element[1].key);
	EXPECT_EQ(2, hash_count(ht));
	EXPECT_FALSE(hash_get(ht, element[1].key));

	hash_destroy(ht);
}

TEST_F(vmad_hash, ti_8) {
	hash_t ht;
	struct element element[] = {{12345, 1}, {(hash_key_t)-12345, 2}, {0, 3}};
	size_t i;

	ht = hash_create(NULL, 5);
	ASSERT_TRUE(ht);
	ASSERT_EQ(5, hash_size(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		EXPECT_TRUE(hash_put(ht, element[i].key, &element[i]));
	}
	EXPECT_EQ(3, hash_count(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		hash_del(ht, element[i].key);
	}
	EXPECT_EQ(0, hash_count(ht));

	hash_destroy(ht);
}

TEST_F(vmad_hash, ti_9) {
	hash_t ht;
	struct element element[] = {{12345, 1}, {1234, 2}, {12, 3}};
	struct element *e;
	size_t i;

	ht = hash_create(NULL, 3);
	ASSERT_TRUE(ht);
	ASSERT_EQ(3, hash_size(ht));

	for (i = 0; i < ARRAY_SIZE(element); i++) {
		EXPECT_TRUE(hash_put(ht, element[i].key, &element[i]));
	}
	EXPECT_EQ(3, hash_count(ht));

	for (i = 0; i < 256; i++) {
		hash_del(ht, element[1].key);
		ASSERT_EQ(2, hash_count(ht));

		element[1].value = i;
		e = (struct element *)hash_put(ht, element[1].key, &element[1]);
		ASSERT_TRUE(e);
		ASSERT_EQ(3, hash_count(ht));
		ASSERT_EQ(((uintptr_t)&element[1]), ((uintptr_t)e));

		e = (struct element *)hash_get(ht, element[1].key);
		ASSERT_TRUE(e);
		ASSERT_EQ(((uintptr_t)&element[1]), ((uintptr_t)e));
		ASSERT_EQ(i, e->value);
	}

	hash_destroy(ht);
}
