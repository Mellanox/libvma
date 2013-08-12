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


#ifndef DEMOCOLLMGR_H_
#define DEMOCOLLMGR_H_

#include "cache_subject_observer.h"
#include "DemoSubject.h"

class Demo_Coll_Mgr1 : public cache_table_mgr<key_class<demo_subject_1_key_t>, demo_subject_1_value_t>
{
public:
	Demo_Coll_Mgr1();
	virtual ~Demo_Coll_Mgr1();
	virtual Demo_Subject1* create_new_entry(key_class<demo_subject_1_key_t>, const observer*);
};

class Demo_Coll_Mgr2 : public cache_table_mgr<key_class<demo_subject_2_key_t>, demo_subject_2_value_t>
{
public:
	Demo_Coll_Mgr2();
	virtual ~Demo_Coll_Mgr2();
	virtual Demo_Subject2* create_new_entry(key_class<demo_subject_2_key_t>, const observer*);
};

#endif /* DEMOCOLLMGR_H_ */
