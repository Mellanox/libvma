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
 *
 *
 * DemoSubject.h
 *
 */


#include "DemoSubject.h"

Demo_Subject1::Demo_Subject1(demo_subject_1_key_t key_1)
	: cache_entry_subject<key_class<demo_subject_1_key_t>, demo_subject_1_value_t>(key_class<demo_subject_1_key_t>(key_1), "lock: Demo_Subject1")
{

	printf("new subject of type 1: \n");

	printf("\t key = %c, no value \n", key_1);

}

Demo_Subject1::Demo_Subject1(demo_subject_1_key_t key_1, demo_subject_1_value_t val_1)
	: cache_entry_subject<key_class<demo_subject_1_key_t>, demo_subject_1_value_t>(key_class<demo_subject_1_key_t>(key_1))
{

	set_val(val_1);

	printf("new subject of type 1: \n");

	printf("\t key = %c, value = %d\n", key_1, val_1);

}

Demo_Subject1::~Demo_Subject1()
{

}

Demo_Subject2::Demo_Subject2(demo_subject_2_key_t key_2)
	: cache_entry_subject<key_class<demo_subject_2_key_t>, demo_subject_2_value_t>(key_class<demo_subject_2_key_t>(key_2), "lock: Demo_Subject2")
{

	printf("new subject of type 2: \n");

	printf("\t key = %d, no value \n", key_2);

}

Demo_Subject2::Demo_Subject2(demo_subject_2_key_t key_2, demo_subject_2_value_t val_2)
	: cache_entry_subject<key_class<demo_subject_2_key_t>, demo_subject_2_value_t>(key_class<demo_subject_2_key_t>(key_2))
{

	set_val(val_2);

	printf("new subject of type 1: \n");

	printf("\t key = %d, value = %d\n", key_2, val_2);

}

Demo_Subject2::~Demo_Subject2() 
{

}
