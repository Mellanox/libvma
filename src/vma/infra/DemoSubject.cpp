/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 *
 * DemoSubject.h
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
