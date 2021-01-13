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
 * DemoSubject.h
 *
 */

#ifndef DEMOSUBJECT_H_
#define DEMOSUBJECT_H_

#include "cache_subject_observer.h"
#include <stdio.h>

template <class Key>
class key_class : public tostr
{
public:
	key_class(Key key) { m_key = (uint32_t)key; };
	key_class(){};

	const std::string to_str() const
	{
		char s[20];
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		snprintf(s, sizeof(s), "%d.%d.%d.%d", NIPQUAD(m_key));
		return(std::string(s));
	}

	void set_actual_key(Key key) { m_key = (uint32_t)key; };

	uint32_t get_actual_key() { return m_key; };
private:
	uint32_t m_key;
};

typedef char 	demo_subject_1_key_t;
typedef int	demo_subject_1_value_t;
typedef cache_entry_subject<key_class<demo_subject_1_key_t>, demo_subject_1_value_t> Demo_Subject1_t;

class Demo_Subject1 : public Demo_Subject1_t
{
public:
	Demo_Subject1(demo_subject_1_key_t key_1);
	Demo_Subject1(demo_subject_1_key_t key_1, demo_subject_1_value_t val_1);

	virtual inline bool 	get_val(INOUT demo_subject_1_value_t & val) { val = m_val; return true; };

	inline void 		update_val(IN demo_subject_1_value_t & val) { this->set_val(val); };

	virtual ~Demo_Subject1();
};

typedef int 	demo_subject_2_key_t;
typedef uint 	demo_subject_2_value_t;

class Demo_Subject2 : public cache_entry_subject<key_class<demo_subject_2_key_t>, demo_subject_2_value_t>
{
public:
	Demo_Subject2(demo_subject_2_key_t key_2);
	Demo_Subject2(demo_subject_2_key_t key_2, demo_subject_2_value_t val_2);

	virtual inline bool 	get_val(INOUT demo_subject_2_value_t & val) { val = m_val; return true; };

	inline void 	update_val(IN demo_subject_2_value_t & val) { this->set_val(val); };

	virtual ~Demo_Subject2();
};

#endif /* DEMOSUBJECT_H_ */
