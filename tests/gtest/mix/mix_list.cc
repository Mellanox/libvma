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

#include "mix_base.h"

#include "src/vma/util/list.h"

struct element {
	struct list_head item;
	int value;
};

class mix_list : public mix_base {};

TEST_F(mix_list, ti_1) {
	struct list_head head;

	INIT_LIST_HEAD(&head);
	ASSERT_TRUE(head.next == &head);
	ASSERT_TRUE(head.prev == &head);
	ASSERT_TRUE(list_empty(&head));
}

TEST_F(mix_list, ti_2) {
	struct element element;
	struct element *cur_element = NULL;

	element.value = 12345;

	cur_element = list_entry(&element.item, struct element, item);

	ASSERT_EQ(12345, cur_element->value);
}

TEST_F(mix_list, ti_3) {
	struct list_head head;
	struct element element;

	INIT_LIST_HEAD(&head);
	list_add(&element.item, &head);

	ASSERT_TRUE(head.next == &element.item);
	ASSERT_TRUE(head.prev == &element.item);
	ASSERT_TRUE(element.item.next == &head);
	ASSERT_TRUE(element.item.prev == &head);
	ASSERT_FALSE(list_empty(&head));
}

TEST_F(mix_list, ti_4) {
	struct list_head head;
	struct element element;
	struct element *cur_element = NULL;

	INIT_LIST_HEAD(&head);
	element.value = 12345;
	list_add(&element.item, &head);

	ASSERT_FALSE(list_empty(&head));

	cur_element = list_first_entry(&head, struct element, item);

	ASSERT_EQ(12345, cur_element->value);
}

TEST_F(mix_list, ti_5) {
	struct list_head head;
	int reference[] = {-12345, 12345, 0};
	struct element element[sizeof(reference)];
	struct list_head *cur_entry = NULL;
	struct element *cur_element = NULL;
	int i = 0;

	INIT_LIST_HEAD(&head);
	i = 0;
	element[i].value = reference[i];
	list_add(&element[i].item, &head);
	i++;
	element[i].value = reference[i];
	list_add(&element[i].item, &head);
	i++;
	element[i].value = reference[i];
	list_add(&element[i].item, &head);

	ASSERT_FALSE(list_empty(&head));

	i = 1;
	list_for_each(cur_entry, &head) {
		cur_element = list_entry(cur_entry, struct element, item);
		ASSERT_EQ(reference[ARRAY_SIZE(reference) - i], cur_element->value);
		i++;
	}
}

TEST_F(mix_list, ti_6) {
	struct list_head head;
	struct element element;

	INIT_LIST_HEAD(&head);
	list_add_tail(&element.item, &head);

	ASSERT_TRUE(head.prev == &element.item);
	ASSERT_TRUE(head.next == &element.item);
	ASSERT_TRUE(element.item.prev == &head);
	ASSERT_TRUE(element.item.next == &head);
	ASSERT_FALSE(list_empty(&head));
}

TEST_F(mix_list, ti_7) {
	struct list_head head;
	struct element element;

	INIT_LIST_HEAD(&head);
	element.value = 12345;
	list_add_tail(&element.item, &head);

	ASSERT_FALSE(list_empty(&head));
	ASSERT_TRUE(list_is_last(&element.item, &head));
}

TEST_F(mix_list, ti_8) {
	struct list_head head;
	int reference[] = {-12345, 12345, 0};
	struct element element[sizeof(reference)];
	struct list_head *cur_entry = NULL;
	struct element *cur_element = NULL;
	int i = 0;

	INIT_LIST_HEAD(&head);
	i = 0;
	element[i].value = reference[i];
	list_add_tail(&element[i].item, &head);
	i++;
	element[i].value = reference[i];
	list_add_tail(&element[i].item, &head);
	i++;
	element[i].value = reference[i];
	list_add_tail(&element[i].item, &head);

	ASSERT_FALSE(list_empty(&head));

	i = 0;
	list_for_each(cur_entry, &head) {
		cur_element = list_entry(cur_entry, struct element, item);
		ASSERT_EQ(reference[i], cur_element->value);
		i++;
	}
}

TEST_F(mix_list, ti_9) {
	struct list_head head;
	struct element element;

	INIT_LIST_HEAD(&head);
	list_add(&element.item, &head);

	ASSERT_FALSE(list_empty(&head));

	list_del(&element.item);

	ASSERT_TRUE(list_empty(&head));
	ASSERT_FALSE(list_empty(&element.item));
}

TEST_F(mix_list, ti_10) {
	struct list_head head;
	struct element element;

	INIT_LIST_HEAD(&head);
	list_add(&element.item, &head);

	ASSERT_FALSE(list_empty(&head));

	list_del_init(&element.item);

	ASSERT_TRUE(list_empty(&head));
	ASSERT_TRUE(list_empty(&element.item));
}
