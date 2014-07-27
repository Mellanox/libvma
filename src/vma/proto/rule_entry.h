/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef RULE_ENTRY_H
#define RULE_ENTRY_H

#include "vma/infra/cache_subject_observer.h"
#include "vma/proto/rule_table_key.h"
#include "rule_val.h"


// This class represent an entry in rule table cashed history.
class rule_entry : public cache_entry_subject<rule_table_key, rule_val*>
{
public:
	friend class rule_table_mgr;

	rule_entry(rule_table_key rrk);

	bool 		get_val(INOUT rule_val* &val);
	void 		set_val(IN rule_val* &val);

	inline void 	set_entry_valid() 	{ m_is_valid = true; }
	inline bool	is_valid()		{ return m_is_valid && m_val && m_val->is_valid(); }; 

	void 		set_str();
	const string 	to_str() const 		{ return m_str; };

private:
	bool 	m_is_valid;
	string 	m_str;

};

#endif /* RULE_ENTRY_H */
