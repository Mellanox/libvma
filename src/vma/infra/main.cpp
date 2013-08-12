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


#include "DemoObserver.h"

int main()
{

	Demo_Observer *o1 = new Demo_Observer();
	Demo_Observer *o2 = new Demo_Observer();

	//collection mgr, subjects type-1
	Demo_Coll_Mgr1 *coll_for_subjects_1 = new Demo_Coll_Mgr1();
	//collection mgr, subjects type-2
	Demo_Coll_Mgr2 *coll_for_subjects_2 = new Demo_Coll_Mgr2();

	o1->register_to_subjects(coll_for_subjects_1, coll_for_subjects_2);
	o2->register_to_subjects(coll_for_subjects_1, coll_for_subjects_2);

	o1->start_test(coll_for_subjects_1, coll_for_subjects_2);

	return 0;
}

