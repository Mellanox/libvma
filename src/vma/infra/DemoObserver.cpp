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
 *
 *
 * DemoObserver.cpp
 *
 */

#include "DemoObserver.h"

Demo_Observer::Demo_Observer() : cache_observer()
{
	printf("created observer: id = %p\n", this);
}

void Demo_Observer::notify_cb()
{
	set_state(false);
	printf("observer %p was notified\n", this);
};

void Demo_Observer::register_to_subjects(Demo_Coll_Mgr1 *coll_for_subjects_1, Demo_Coll_Mgr2 *coll_for_subjects_2)
{
	Demo_Subject1* s1 = NULL;
	Demo_Subject2* s2 = NULL;
	key_class<char> c('a');
	key_class<int> i(1);
	char ch='a';
	int in=1;

	// ######################### create collections of subjects type 1+2 ######################### //
	for(; ch < 'f' && in < 6; ch++, in++)
	{
		c.set_actual_key(ch);
		coll_for_subjects_1->register_observer(c, this, (cache_entry_subject<key_class<demo_subject_1_key_t>,demo_subject_1_value_t> **)&s1); // registered for subject1 with key 'a'
		m_subjects_1_list.insert(pair<demo_subject_1_key_t, Demo_Subject1 *>(c.get_actual_key(), s1));
		i.set_actual_key(in);
		coll_for_subjects_2->register_observer(i, this, (cache_entry_subject<key_class<demo_subject_2_key_t>,demo_subject_2_value_t> **)&s2); // registered for subject2 with key 1
		m_subjects_2_list.insert(pair<demo_subject_2_key_t, Demo_Subject2 *>(i.get_actual_key(), s2));
	}

}

void Demo_Observer::update_subject_1(demo_subject_1_key_t key, demo_subject_1_value_t value)
{
	Demo_Subject1 *s1 = m_subjects_1_list.find(key)->second; //find subject corresponding to key in the list
	if (s1)
	{
		s1->update_val(value); // expected output: notification msg
		s1->notify_observers();
	}
	else
		printf("subject corresponding to key wasn't found\n");
}

void Demo_Observer::get_subject_1(demo_subject_1_key_t key)
{
	demo_subject_1_value_t val_s1;
	Demo_Subject1 *s1 = m_subjects_1_list.find(key)->second; //find subject corresponding to key in the list
	if (s1)
	{
		s1->get_val(val_s1);
		printf("subject1: key = %c, val = %d\n", key, val_s1);
	}
	else
		printf("subject corresponding to key wasn't found\n");
}

void Demo_Observer::update_subject_2(demo_subject_2_key_t key, demo_subject_2_value_t value)
{
	Demo_Subject2 *s2 = m_subjects_2_list.find(key)->second; //find subject corresponding to key in the list
	if (s2)
	{
		s2->update_val(value); // expected output: notification msg
		s2->notify_observers();
	}
	else
		printf("subject corresponding to key wasn't found\n");
}

void Demo_Observer::get_subject_2(demo_subject_2_key_t key)
{
	demo_subject_2_value_t val_s2;
	Demo_Subject2 *s2 = m_subjects_2_list.find(key)->second; //find subject corresponding to key in the list
	if (s2)
	{
		s2->get_val(val_s2);
		printf("subject2: key = %d, val = %d\n", key, val_s2);
	}
	else
		printf("subject corresponding to key wasn't found\n");
}

bool Demo_Observer::start_test(Demo_Coll_Mgr1 *coll_for_subjects_1, Demo_Coll_Mgr2 *coll_for_subjects_2)
{
	update_subject_1('a', 12);

	update_subject_1('b', 13);

	update_subject_1('c', 14);

	get_subject_1('a'); // expected output: val = 12

	update_subject_2(1, 1000);

	update_subject_2(2, 2000);

	get_subject_2(1); // expected output: val = 2000

	coll_for_subjects_1->unregister_observer('a', this);
	//m_subjects_1_list.erase('a'); // supposed to remove from m_subjects_1_list, left for testing

	update_subject_1('a', 15); // only other observer is notified

	coll_for_subjects_2->unregister_observer(2, this);

	return true;

}

Demo_Observer::~Demo_Observer()
{

}

