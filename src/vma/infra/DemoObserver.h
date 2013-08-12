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
 * DemoObserver.h
 *
 */

#ifndef DEMOOBSERVER_H_
#define DEMOOBSERVER_H_

#include <stdlib.h>
#include <stdio.h>
#include <map>
#include "cache_subject_observer.h"
#include "DemoSubject.h"
#include "DemoCollMgr.h"
using namespace std;

class Demo_Observer : public cache_observer
{
public:
	Demo_Observer();
	virtual ~Demo_Observer();

	void register_to_subjects(Demo_Coll_Mgr1 *coll_for_subjects_1, Demo_Coll_Mgr2 *coll_for_subjects_2);
	bool start_test(Demo_Coll_Mgr1 *coll_for_subjects_1, Demo_Coll_Mgr2 *coll_for_subjects_2);

	void notify_cb(); //hide cache_observer function for testing

private:

	void update_subject_1(demo_subject_1_key_t key, demo_subject_1_value_t value); //sets value of subject type-1 corresponding to key
	void update_subject_2(demo_subject_2_key_t key, demo_subject_2_value_t value); //sets value of subject type-2 corresponding to key

	void get_subject_1(demo_subject_1_key_t key); //prints value of subject type-1 corresponding to key
	void get_subject_2(demo_subject_2_key_t key); //prints value of subject type-2 corresponding to key

	//Demo_Coll_Mgr1* m_coll_for_subjects_1; //collection mgr for subjects type-1
	//Demo_Coll_Mgr2* m_coll_for_subjects_2; //collection mgr for subjects type-2

	map<demo_subject_1_key_t, Demo_Subject1*> m_subjects_1_list; //list of observed subjects type-1
	map<demo_subject_2_key_t, Demo_Subject2*> m_subjects_2_list; //list of observed subjects type-2

};

#endif /* DEMOOBSERVER_H_ */
