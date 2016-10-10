/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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

#include "vlogger/vlogger.h"
#include "utils/bullseye.h"
#include "netlink_wrapper.h"

os_network_data_wrapper* g_p_os_wrapper = NULL;
 
bool netlink_wrapper::route_resolve(route_lookup_key key, route_val *found_route_val, long timeout_usec)
{
	return m_nl_sock_mgr.route_resolve(key, found_route_val, timeout_usec);
}

int netlink_wrapper::get_channel() 
{
	return m_nl_cache_mgr.get_channel();
}

bool netlink_wrapper::register_event(e_os_network_data_event_type type, const observer* new_obs) 
{
	return m_nl_cache_mgr.register_event(type, new_obs);;
}
 
bool netlink_wrapper::unregister(e_os_network_data_event_type type, const observer* obs) 
{
	return m_nl_cache_mgr.unregister(type, obs);	
}
 
int netlink_wrapper::handle_events() 
{
	return m_nl_cache_mgr.handle_events();
}
 
int netlink_wrapper::open_channel() 
{
	return m_nl_cache_mgr.open_channel();
}
 
int netlink_wrapper::get_neigh(const char* ipaddr, int ifindex, netlink_neigh_info* new_neigh_info) 
{
	return m_nl_cache_mgr.get_neigh(ipaddr, ifindex, new_neigh_info);
}
 
void netlink_wrapper::neigh_timer_expired() 
{
	m_nl_cache_mgr.neigh_timer_expired();
}
