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
