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

