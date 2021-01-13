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
