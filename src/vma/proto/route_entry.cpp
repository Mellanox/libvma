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


#include "vma/proto/ip_address.h"
#include "vma/event/route_net_dev_event.h"
#include "route_entry.h"
#include "route_table_mgr.h"
#include "vma/infra/cache_subject_observer.h"

// debugging macros
#define MODULE_NAME 		"rte"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[%s]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_str.c_str()

#define rt_entry_logdbg		__log_info_dbg

route_entry::route_entry(route_table_key rtk) :
	cache_entry_subject<route_table_key,route_val*>(rtk), cache_observer(),
	m_p_net_dev_entry(NULL),
	m_p_net_dev_val(NULL),
	m_b_offloaded_net_dev(false),
	m_is_valid(false)
{
	m_val = NULL;
}

bool route_entry::get_val(INOUT route_val* &val)
{
	rt_entry_logdbg("");
	val = m_val;
	return is_valid();
}

void route_entry::set_str()
{
	m_str = get_key().to_str() + "->" + m_val->get_if_name();
}

void route_entry::set_val(IN route_val* &val)
{
	cache_entry_subject<route_table_key, route_val*>::set_val(val);
	set_str();
}

void route_entry::register_to_net_device()
{
	ip_address src_addr = m_val->get_src_addr();

	rt_entry_logdbg("register to net device with src_addr %s", src_addr.to_str().c_str());

	cache_entry_subject<ip_address, net_device_val*> *net_dev_entry = (cache_entry_subject<ip_address, net_device_val*> *)m_p_net_dev_entry;
	if (g_p_net_device_table_mgr->register_observer(src_addr, this, &net_dev_entry)) {
		rt_entry_logdbg("route_entry [%p] is registered to an offloaded device", this);
		m_p_net_dev_entry = (net_device_entry *) net_dev_entry;
		m_p_net_dev_entry->get_val(m_p_net_dev_val);
		m_b_offloaded_net_dev = true;
	} 
	else {
		rt_entry_logdbg("route_entry [%p] tried to register to non-offloaded device ---> registration failed", this);
		m_b_offloaded_net_dev = false;
	}
}

void route_entry::unregister_to_net_device()
{
	if (!m_val) {
		rt_entry_logdbg("ERROR: failed to find route val");
		return;
	}

	ip_address src_addr = m_val->get_src_addr();

	if (m_b_offloaded_net_dev) {
		rt_entry_logdbg("unregister to net device with src_addr %s", src_addr.to_str().c_str());
		if (! g_p_net_device_table_mgr->unregister_observer(src_addr, this)) {
			rt_entry_logdbg("ERROR: failed to unregister from net_device_entry");
		}
	}

	m_p_net_dev_entry = NULL;
	m_p_net_dev_val = NULL;

}

void route_entry::notify_cb()
{
	// got addr_change event from net_device_entry --> does not change the validity of route_entry!
	rt_entry_logdbg("");
	if (m_p_net_dev_entry->is_valid()) {
		m_p_net_dev_entry->get_val(m_p_net_dev_val);
	}
	else {
		m_p_net_dev_val = NULL;
	}
	notify_observers();
}
