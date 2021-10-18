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


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "utils/bullseye.h"
#include "utils/lock_wrapper.h"
#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/utils.h"
#include "route_table_mgr.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/sock/sock-redirect.h"
#include "vma/dev/net_device_table_mgr.h"
#include "ip_address.h"

// debugging macros
#define MODULE_NAME 		"rtm:"
#define rt_mgr_if_logpanic	__log_panic
#define	rt_mgr_logerr		__log_err
#define rt_mgr_logwarn		__log_warn
#define rt_mgr_loginfo		__log_info
#define rt_mgr_logdbg		__log_dbg
#define rt_mgr_logfunc		__log_func
#define rt_mgr_logfuncall	__log_funcall

route_table_mgr* g_p_route_table_mgr = NULL;

route_table_mgr::route_table_mgr() : netlink_socket_mgr<route_val>(ROUTE_DATA_TYPE), cache_table_mgr<route_rule_table_key, route_val*>("route_table_mgr")
{
	rt_mgr_logdbg("");

	//Read Route table from kernel and save it in local variable. 
	update_tbl();

	// create route_entry for each net_dev- needed for receiving port up/down events for net_dev_entry
	route_val *p_val;
	for (int i = 0; i < m_tab.entries_num; i++)
	{
		p_val = &m_tab.value[i];
		in_addr_t src_addr = p_val->get_src_addr();
		in_addr_route_entry_map_t::iterator iter = m_rte_list_for_each_net_dev.find(src_addr);
		// if src_addr of interface exists in the map, no need to create another route_entry
		if (iter == m_rte_list_for_each_net_dev.end()) {
			in_addr_t dst_ip	= src_addr;
			in_addr_t src_ip	= 0;
			uint8_t tos		= 0;
			m_rte_list_for_each_net_dev[src_addr] = create_new_entry(route_rule_table_key(dst_ip, src_ip, tos), NULL);
		}
	}

	//Print table
	print_val_tbl();
	
	// register to netlink event
	g_p_netlink_handler->register_event(nlgrpROUTE, this);
	rt_mgr_logdbg("Registered to g_p_netlink_handler");

	rt_mgr_logdbg("Done");
}

route_table_mgr::~route_table_mgr()
{
	rt_mgr_logdbg("");

	// clear all route_entrys created in the constructor
	in_addr_route_entry_map_t::iterator iter;

	while ((iter = m_rte_list_for_each_net_dev.begin()) != m_rte_list_for_each_net_dev.end()) {
		delete(iter->second);
		m_rte_list_for_each_net_dev.erase(iter);
	}

	rt_tbl_cach_entry_map_t::iterator cache_itr;
	while ((cache_itr = m_cache_tbl.begin()) != m_cache_tbl.end()) {
		delete(cache_itr->second);
		m_cache_tbl.erase(cache_itr);
	}
	rt_mgr_logdbg("Done");
}

void route_table_mgr::update_tbl()
{
	auto_unlocker lock(m_lock);

	netlink_socket_mgr<route_val>::update_tbl();

	rt_mgr_update_source_ip();

	return;
}

void route_table_mgr::rt_mgr_update_source_ip()
{
	route_val *p_val;
	//for route entries which still have no src ip and no gw
	for (int i = 0; i < m_tab.entries_num; i++) {
		p_val = &m_tab.value[i];
		if (p_val->get_src_addr() || p_val->get_gw_addr()) continue;
		if (g_p_net_device_table_mgr) { //try to get src ip from net_dev list of the interface
			in_addr_t longest_prefix = 0;
			in_addr_t correct_src = 0;
			local_ip_list_t::iterator lip_iter;
			local_ip_list_t lip_offloaded_list = g_p_net_device_table_mgr->get_ip_list(p_val->get_if_index());
			if (!lip_offloaded_list.empty()) {
				for (lip_iter = lip_offloaded_list.begin(); lip_offloaded_list.end() != lip_iter; lip_iter++)
				{
					ip_data_t ip = *lip_iter;
					if((p_val->get_dst_addr() & ip.netmask) == (ip.local_addr & ip.netmask)) { //found a match in routing table
						if((ip.netmask | longest_prefix) != longest_prefix){
							longest_prefix = ip.netmask; // this is the longest prefix match
							correct_src = ip.local_addr;
						}
					}
				}
				if (correct_src) {
					p_val->set_src_addr(correct_src);
					continue;
				}
			}
		}
		// if still no src ip, get it from ioctl
		struct sockaddr_in src_addr;
		char *if_name = (char *)p_val->get_if_name();
		if (!get_ipv4_from_ifname(if_name, &src_addr)) {
			p_val->set_src_addr(src_addr.sin_addr.s_addr);
		}
		else {
			// Failed mapping if_name to IPv4 address
			rt_mgr_logwarn("could not figure out source ip for rtv = %s", p_val->to_str());
		}
	}

	//for route entries with gateway, do recursive search for src ip
	int num_unresolved_src = m_tab.entries_num;
	int prev_num_unresolved_src = 0;
	do {
		prev_num_unresolved_src = num_unresolved_src;
		num_unresolved_src = 0;
		for (int i = 0; i < m_tab.entries_num; i++) {
			p_val = &m_tab.value[i];
			if (p_val->get_gw_addr() && !p_val->get_src_addr()) {
				route_val* p_val_dst;
				in_addr_t in_addr = p_val->get_gw_addr();
				unsigned char table_id = p_val->get_table_id();
				if (find_route_val(in_addr, table_id, p_val_dst)) {
					if (p_val_dst->get_src_addr()) {
						p_val->set_src_addr(p_val_dst->get_src_addr());
					} else if (p_val == p_val_dst) { //gateway of the entry lead to same entry
						local_ip_list_t::iterator lip_iter;
						local_ip_list_t lip_offloaded_list = g_p_net_device_table_mgr->get_ip_list(p_val->get_if_index());
						for (lip_iter = lip_offloaded_list.begin(); lip_offloaded_list.end() != lip_iter; lip_iter++)
						{
							ip_data_t ip = *lip_iter;
							if(p_val->get_gw_addr() == ip.local_addr) {
								p_val->set_gw(0);
								p_val->set_src_addr(ip.local_addr);
								break;
							}
						}
						if (!p_val->get_src_addr())
							num_unresolved_src++;
					} else {
						num_unresolved_src++;
					}
					// gateway and source are equal, no need of gw.
					if (p_val->get_src_addr() == p_val->get_gw_addr()) {
						p_val->set_gw(0);
					}
				} else {
					num_unresolved_src++;
				}
			}
		}
	} while (num_unresolved_src && prev_num_unresolved_src > num_unresolved_src);

	//for route entries which still have no src ip
	for (int i = 0; i < m_tab.entries_num; i++) {
		p_val = &m_tab.value[i];
		if (p_val->get_src_addr()) continue;
		if (p_val->get_gw_addr()) {
			rt_mgr_logdbg("could not figure out source ip for gw address. rtv = %s", p_val->to_str());
		}
		// if still no src ip, get it from ioctl
		struct sockaddr_in src_addr;
		char *if_name = (char *)p_val->get_if_name();
		if (!get_ipv4_from_ifname(if_name, &src_addr)) {
			p_val->set_src_addr(src_addr.sin_addr.s_addr);
		}
		else {
			// Failed mapping if_name to IPv4 address
			rt_mgr_logdbg("could not figure out source ip for rtv = %s", p_val->to_str());
		}
	}
}

bool route_table_mgr::parse_enrty(nlmsghdr *nl_header, route_val *p_val)
{
	int len;
	struct rtmsg *rt_msg;
	struct rtattr *rt_attribute;

	// get route entry header
	rt_msg = (struct rtmsg *) NLMSG_DATA(nl_header);

	// we are not concerned about the local and default route table
	if (rt_msg->rtm_family != AF_INET || rt_msg->rtm_table == RT_TABLE_LOCAL)
		return false;

	p_val->set_protocol(rt_msg->rtm_protocol);
	p_val->set_scope(rt_msg->rtm_scope);
	p_val->set_type(rt_msg->rtm_type);
	p_val->set_table_id(rt_msg->rtm_table);

	in_addr_t dst_mask = htonl(VMA_NETMASK(rt_msg->rtm_dst_len));
	p_val->set_dst_mask(dst_mask);
	p_val->set_dst_pref_len(rt_msg->rtm_dst_len);

	len = RTM_PAYLOAD(nl_header);
	rt_attribute = (struct rtattr *) RTM_RTA(rt_msg);

	for (;RTA_OK(rt_attribute, len);rt_attribute=RTA_NEXT(rt_attribute,len)) {
		parse_attr(rt_attribute, p_val);
	}
	p_val->set_state(true);
	p_val->set_str();
	return true;
}

void route_table_mgr::parse_attr(struct rtattr *rt_attribute, route_val *p_val)
{
	switch (rt_attribute->rta_type) {
	case RTA_DST:
		p_val->set_dst_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	// next hop IPv4 address
	case RTA_GATEWAY:
		p_val->set_gw(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	// unique ID associated with the network interface
	case RTA_OIF:
		p_val->set_if_index(*(int *)RTA_DATA(rt_attribute));
		char if_name[IFNAMSIZ];
		if_indextoname(p_val->get_if_index(),if_name);
		p_val->set_if_name(if_name);
		break;
	case RTA_SRC:
	case RTA_PREFSRC:
		p_val->set_src_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	case RTA_TABLE:
		p_val->set_table_id(*(uint32_t *)RTA_DATA(rt_attribute));
		break;
	case RTA_METRICS:
	{
		struct rtattr *rta = (struct rtattr *)RTA_DATA(rt_attribute);
		int len = RTA_PAYLOAD(rt_attribute);
		uint16_t type;
		while (RTA_OK(rta, len)) {
			type = rta->rta_type;
			switch (type) {
			case RTAX_MTU:
				p_val->set_mtu(*(uint32_t *)RTA_DATA(rta));
				break;
			default:
				rt_mgr_logdbg("got unexpected METRICS %d %x",
					type, *(uint32_t *)RTA_DATA(rta));
				break;
			}
			rta = RTA_NEXT(rta, len);
		}
		break;
	}
	default:
		rt_mgr_logdbg("got unexpected type %d %x", rt_attribute->rta_type,
				*(uint32_t *)RTA_DATA(rt_attribute));
		break;
	}
}

bool route_table_mgr::find_route_val(in_addr_t &dst, unsigned char table_id, route_val* &p_val)
{
	ip_address dst_addr = dst;
	rt_mgr_logfunc("dst addr '%s'", dst_addr.to_str().c_str());

	route_val *correct_route_val = NULL;
	int longest_prefix = -1;

	for (int i = 0; i < m_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_tab.value[i];
		if (!p_val_from_tbl->is_deleted() && p_val_from_tbl->is_if_up()) { // value was not deleted
			if(p_val_from_tbl->get_table_id() == table_id) { //found a match in routing table ID
				if(p_val_from_tbl->get_dst_addr() == (dst & p_val_from_tbl->get_dst_mask())) { //found a match in routing table
					if(p_val_from_tbl->get_dst_pref_len() > longest_prefix) { // this is the longest prefix match
						longest_prefix = p_val_from_tbl->get_dst_pref_len();
						correct_route_val = p_val_from_tbl;
					}
				}
			}
		}	
	}
	if (correct_route_val) {
		ip_address dst_gw = correct_route_val->get_dst_addr();
		p_val = correct_route_val;
		rt_mgr_logdbg("found route val[%p]: %s", p_val, p_val->to_str());
		return true;
	}

	rt_mgr_logdbg("destination gw wasn't found");
	return false;
}

bool route_table_mgr::route_resolve(IN route_rule_table_key key, OUT route_result &res)
{
	in_addr_t dst = key.get_dst_ip();
	ip_address dst_addr = dst;
	rt_mgr_logdbg("dst addr '%s'", dst_addr.to_str().c_str());

	route_val *p_val = NULL;
	std::deque<unsigned char> table_id_list;
	
	g_p_rule_table_mgr->rule_resolve(key, table_id_list);

	auto_unlocker lock(m_lock);
	std::deque<unsigned char>::iterator table_id_iter = table_id_list.begin();
	for (; table_id_iter != table_id_list.end(); table_id_iter++) {
		if (find_route_val(dst, *table_id_iter, p_val)) {
			res.p_src = p_val->get_src_addr();
			rt_mgr_logdbg("dst ip '%s' resolved to src addr "
					"'%d.%d.%d.%d'", dst_addr.to_str().c_str(),
					NIPQUAD(res.p_src));
			res.p_gw = p_val->get_gw_addr();
			rt_mgr_logdbg("dst ip '%s' resolved to gw addr '%d.%d.%d.%d'",
					dst_addr.to_str().c_str(), NIPQUAD(res.p_gw));
			res.mtu = p_val->get_mtu();
			rt_mgr_logdbg("found route mtu %d", res.mtu);
			return true;
		}
	}
	/* prevent usage on false return */
	return false;
}

void route_table_mgr::update_entry(INOUT route_entry* p_ent, bool b_register_to_net_dev /*= false*/)
{
	rt_mgr_logdbg("entry [%p]", p_ent);
	auto_unlocker lock(m_lock);
	if (p_ent && !p_ent->is_valid()) { //if entry is found in the collection and is not valid
		rt_mgr_logdbg("route_entry is not valid-> update value");
		rule_entry* p_rr_entry = p_ent->get_rule_entry();
		std::deque<rule_val*>* p_rr_val;
		if (p_rr_entry && p_rr_entry->get_val(p_rr_val)) {
			route_val* p_val = NULL;
			in_addr_t peer_ip = p_ent->get_key().get_dst_ip();
			unsigned char table_id;
			for (std::deque<rule_val*>::iterator p_rule_val = p_rr_val->begin(); p_rule_val != p_rr_val->end(); p_rule_val++) {
				table_id = (*p_rule_val)->get_table_id();
				if (find_route_val(peer_ip, table_id, p_val)) {
					p_ent->set_val(p_val);
					if (b_register_to_net_dev) {
						//in_addr_t src_addr = p_val->get_src_addr();
						//net_device_val* p_ndv = g_p_net_device_table_mgr->get_net_device_val(src_addr);
						
						// Check if broadcast IP which is NOT supported
						if (IS_BROADCAST_N(peer_ip)) {
							rt_mgr_logdbg("Disabling Offload for route_entry '%s' - this is BC address", p_ent->to_str().c_str());
							// Need to route traffic to/from OS
							// Prevent registering of net_device to route entry
						}
						// Check if: Local loopback over Ethernet case which was not supported before OFED 2.1
						/*else if (p_ndv && (p_ndv->get_transport_type() == VMA_TRANSPORT_ETH) &&  (peer_ip == src_addr)) {
							rt_mgr_logdbg("Disabling Offload for route_entry '%s' - this is an Ethernet unicast loopback route", p_ent->to_str().c_str());
							// Need to route traffic to/from OS
							// Prevent registering of net_device to route entry
						}*/
						else {
							// register to net device for bonding events
							p_ent->register_to_net_device();
						}
					}
					// All good, validate the new route entry
					p_ent->set_entry_valid();
					break;
				} else {
					rt_mgr_logdbg("could not find route val for route_entry '%s in table %u'", p_ent->to_str().c_str(), table_id);
				}
			}
		}
		else {
			rt_mgr_logdbg("rule entry is not valid");
		}
	}
}

route_entry* route_table_mgr::create_new_entry(route_rule_table_key key, const observer *obs)
{
	// no need for lock - lock is activated in cache_collection_mgr::register_observer

	rt_mgr_logdbg("");
	NOT_IN_USE(obs);
	route_entry* p_ent = new route_entry(key);
	update_entry(p_ent, true);
	rt_mgr_logdbg("new entry %p created successfully", p_ent);
	return p_ent;
}

void route_table_mgr::new_route_event(route_val* netlink_route_val)
{
	if (!netlink_route_val) {
		rt_mgr_logdbg("Invalid route entry");
		return;
	}
	
	if (m_tab.entries_num >= MAX_TABLE_SIZE) {
		rt_mgr_logwarn("No available space for new route entry");	
		return;
	}
	
	auto_unlocker lock(m_lock);	
	route_val* p_route_val = &m_tab.value[m_tab.entries_num];
	p_route_val->set_dst_addr(netlink_route_val->get_dst_addr());
	p_route_val->set_dst_mask(netlink_route_val->get_dst_mask());
	p_route_val->set_dst_pref_len(netlink_route_val->get_dst_pref_len());
	p_route_val->set_src_addr(netlink_route_val->get_src_addr());
	p_route_val->set_gw(netlink_route_val->get_gw_addr());
	p_route_val->set_protocol(netlink_route_val->get_protocol());
	p_route_val->set_scope(netlink_route_val->get_scope()); 
	p_route_val->set_type(netlink_route_val->get_type());
	p_route_val->set_table_id(netlink_route_val->get_table_id());
	p_route_val->set_if_index(netlink_route_val->get_if_index());
	p_route_val->set_if_name(const_cast<char*> (netlink_route_val->get_if_name()));
	p_route_val->set_mtu((netlink_route_val->get_mtu()));
	p_route_val->set_state(true);
	p_route_val->set_str();
	p_route_val->print_val();
	++m_tab.entries_num;
}

void route_table_mgr::notify_cb(event *ev)
{
	rt_mgr_logdbg("received route event from netlink");

	route_nl_event *route_netlink_ev = dynamic_cast <route_nl_event*>(ev);
	if (!route_netlink_ev) {
		rt_mgr_logwarn("Received non route event!!!");
		return;
	}
	
	netlink_route_info* p_netlink_route_info = route_netlink_ev->get_route_info();
	if (!p_netlink_route_info) {
		rt_mgr_logdbg("Received invalid route event!!!");
		return;
	}
	
	switch(route_netlink_ev->nl_type) {
		case RTM_NEWROUTE:
			new_route_event(p_netlink_route_info->get_route_val());
			break;
#if 0
		case RTM_DELROUTE:
			del_route_event(p_netlink_route_info->get_route_val());
			break;
#endif
		default:
			rt_mgr_logdbg("Route event (%u) is not handled", route_netlink_ev->nl_type);
			break;
	}
}
