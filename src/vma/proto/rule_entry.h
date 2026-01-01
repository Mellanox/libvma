/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef RULE_ENTRY_H
#define RULE_ENTRY_H

#include "vma/infra/cache_subject_observer.h"
#include "vma/proto/route_rule_table_key.h"
#include "rule_val.h"


// This class represent an entry in rule table cashed history.
class rule_entry : public cache_entry_subject<route_rule_table_key, std::deque<rule_val*>*>
{
public:
	friend class rule_table_mgr;

	rule_entry(route_rule_table_key rrk);
	
	bool 		get_val(INOUT std::deque<rule_val*>* &val);

	inline bool	is_valid(){ 
		/* TODO for future rules live updates */
		/* for (std::deque<rule_val*>::iterator val = m_val->begin(); val != m_val->end(); val++) {
			if (!(*val)->is_valid()) {
				return false;
			}
		} */	
		return !m_val->empty(); 
	} 

	inline const string to_str() const 		{ return get_key().to_str(); };

private:
	std::deque<rule_val*> values;
};

#endif /* RULE_ENTRY_H */
