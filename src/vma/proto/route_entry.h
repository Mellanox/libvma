/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef ROUTE_ENTRY_H
#define ROUTE_ENTRY_H

#include <net/if.h>
#include <netinet/in.h>

#include "vma/proto/route_table_key.h"
#include "vma/infra/cache_subject_observer.h"
#include "route_val.h"

class route_entry : public cache_entry_subject<route_table_key,route_val*>, public cache_observer
{
public:
	friend class route_table_mgr;

	route_entry(route_table_key rtk);
	virtual ~route_entry() { unregister_to_net_device(); };

	bool 		get_val(INOUT route_val* &val);
	void 		set_val(IN route_val* &val);

	net_device_val* get_net_dev_val()	{ return m_p_net_dev_val; }

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	inline bool 	is_net_dev_offloaded()	{ return m_b_offloaded_net_dev; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	inline void 	set_entry_valid() 	{ m_is_valid = true; }
	inline bool	is_valid()		{ return m_is_valid && m_val && m_val->is_valid(); }; //m_val is NULL at first

	virtual void 	notify_cb();

	void 		set_str();
	const string 	to_str() const 		{ return m_str; };

private:
	net_device_entry* 	m_p_net_dev_entry;
	net_device_val* 	m_p_net_dev_val;
	bool 			m_b_offloaded_net_dev;
	bool 			m_is_valid;
	string			m_str;

	void			register_to_net_device();
	void 			unregister_to_net_device();
};

#endif /* ROUTE_ENTRY_H */
