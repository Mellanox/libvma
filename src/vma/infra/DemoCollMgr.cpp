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


