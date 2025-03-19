/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "DemoCollMgr.h"

Demo_Coll_Mgr1::Demo_Coll_Mgr1() : cache_collection_mgr<key_class<demo_subject_1_key_t>, demo_subject_1_value_t>("lock: Demo_Coll_Mgr1")
{
	printf("created collection mgr: char --> int\n");

}

Demo_Subject1* Demo_Coll_Mgr1::create_new_entry(key_class<demo_subject_1_key_t> key, const observer* obs)
{
	NOT_IN_USE(obs);
	return new Demo_Subject1(key.get_actual_key());
}

Demo_Coll_Mgr1::~Demo_Coll_Mgr1() 
{

}

Demo_Coll_Mgr2::Demo_Coll_Mgr2() : cache_collection_mgr<key_class<demo_subject_2_key_t>, demo_subject_2_value_t>("lock: Demo_Coll_Mgr2")
{
	printf("created collection mgr: int --> uint \n");

}

Demo_Subject2* Demo_Coll_Mgr2::create_new_entry(key_class<demo_subject_2_key_t> key, const observer* obs)
{
	NOT_IN_USE(obs);
	return new Demo_Subject2(key.get_actual_key());
}


Demo_Coll_Mgr2::~Demo_Coll_Mgr2() 
{

}


