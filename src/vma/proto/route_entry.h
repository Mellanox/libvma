/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef ROUTE_ENTRY_H
#define ROUTE_ENTRY_H

#include "vma/util/if.h"
#include <netinet/in.h>

#include "vma/proto/route_rule_table_key.h"
#include "vma/infra/cache_subject_observer.h"
#include "vma/dev/net_device_entry.h"
#include "route_val.h"
#include "rule_entry.h"

class route_entry : public cache_entry_subject<route_rule_table_key,route_val*>, public cache_observer
{
public:
	friend class route_table_mgr;

	route_entry(route_rule_table_key rtk);
	virtual ~route_entry();

	bool 		get_val(INOUT route_val* &val);
	void 		set_val(IN route_val* &val);

	net_device_val* get_net_dev_val()	{ return m_p_net_dev_val; }

	inline void 	set_entry_valid() 	{ m_is_valid = true; }
	inline bool	is_valid()		{ return m_is_valid && m_val && m_val->is_valid(); }; //m_val is NULL at first

	virtual void 	notify_cb();

	void 		set_str();
	const string 	to_str() const 		{ return m_str; };

	inline rule_entry* get_rule_entry() const	{ return m_p_rr_entry; };
	
private:
	net_device_entry* 	m_p_net_dev_entry;
	net_device_val* 	m_p_net_dev_val;
	bool 			m_b_offloaded_net_dev;
	bool 			m_is_valid;
	string			m_str;
	rule_entry*		m_p_rr_entry;

	void			register_to_net_device();
	void 			unregister_to_net_device();
};

#endif /* ROUTE_ENTRY_H */
