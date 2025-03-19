/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
