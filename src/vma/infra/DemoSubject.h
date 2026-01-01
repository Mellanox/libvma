/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 *
 * DemoSubject.h
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
