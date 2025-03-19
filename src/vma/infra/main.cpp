/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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

	delete o1;
	delete o2;
	delete coll_for_subjects_1;
	delete coll_for_subjects_2;

	return 0;
}

