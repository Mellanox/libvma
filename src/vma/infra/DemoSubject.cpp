/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
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
