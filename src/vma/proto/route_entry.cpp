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


#include "vma/proto/ip_address.h"
#include "route_entry.h"
#include "route_table_mgr.h"
#include "vma/infra/cache_subject_observer.h"
#include "vma/dev/net_device_table_mgr.h"

// debugging macros
#define MODULE_NAME 		"rte"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[%s]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_str.c_str()

#define rt_entry_logdbg		__log_info_dbg

route_entry::route_entry(route_rule_table_key rtk) :
	cache_entry_subject<route_rule_table_key,route_val*>(rtk), cache_observer(),
	m_p_net_dev_entry(NULL),
	m_p_net_dev_val(NULL),
	m_b_offloaded_net_dev(false),
	m_is_valid(false)
{
	m_val = NULL;
	m_p_rr_entry = NULL;
	cache_entry_subject<route_rule_table_key, std::deque<rule_val*>*>* rr_entry = NULL;
	g_p_rule_table_mgr->register_observer(rtk, this, &rr_entry);
	m_p_rr_entry = dynamic_cast<rule_entry*>(rr_entry);
}

route_entry::~route_entry() 
{ 
	unregister_to_net_device(); 
	if (m_p_rr_entry) {
		g_p_rule_table_mgr->unregister_observer(get_key(), this);
		m_p_rr_entry = NULL;
	}
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
	cache_entry_subject<route_rule_table_key, route_val*>::set_val(val);
	set_str();
}

void route_entry::register_to_net_device()
{
	local_ip_list_t lip_offloaded_list = g_p_net_device_table_mgr->get_ip_list(m_val->get_if_index());
	if (lip_offloaded_list.empty()) {
		rt_entry_logdbg("No matched net device for %s interface", m_val->get_if_name());
		m_b_offloaded_net_dev = false;
	} else {
		ip_address src_addr = lip_offloaded_list.front().local_addr;
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
}

void route_entry::unregister_to_net_device()
{
	if (!m_val) {
		rt_entry_logdbg("ERROR: failed to find route val");
		return;
	}

	if (m_p_net_dev_val) {
		ip_address src_addr = m_p_net_dev_val->get_local_addr();
		rt_entry_logdbg("unregister from net device with src_addr %s", src_addr.to_str().c_str());
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
