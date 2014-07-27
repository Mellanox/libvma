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

#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/utils.h"
#include "route_table_mgr.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/sock/sock-redirect.h"
#include "lwip/ip_addr.h"
#include "ip_address.h"
#include "vma/util/bullseye.h"

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

route_table_mgr::route_table_mgr() : netlink_socket_mgr<route_val>(ROUTE_DATA_TYPE), cache_table_mgr<route_table_key, route_val*>("route_table_mgr")
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
		std::tr1::unordered_map<in_addr_t, route_entry*>::iterator iter = m_rte_list_for_each_net_dev.find(src_addr);
		// if src_addr of interface exists in the map, no need to create another route_entry
		if (iter == m_rte_list_for_each_net_dev.end()) {
			//Use main route table on initialize.
			m_rte_list_for_each_net_dev.insert(pair<in_addr_t, route_entry*> (src_addr, create_new_entry(route_table_key(src_addr, RT_TABLE_MAIN), NULL)));
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
	std::tr1::unordered_map<in_addr_t, route_entry*>::iterator iter;
	for (iter = m_rte_list_for_each_net_dev.begin(); iter != m_rte_list_for_each_net_dev.end(); iter++) {
		route_entry* p_rte = iter->second;
		delete(p_rte);
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
			net_dev_lst_t* nd_lst = g_p_net_device_table_mgr->get_net_device_val_lst_from_index(p_val->get_if_index());
			if (nd_lst) {
				net_dev_lst_t::iterator iter = nd_lst->begin();
				while (iter != nd_lst->end()) {
					if((p_val->get_dst_addr() & (*iter)->get_netmask()) == ((*iter)->get_local_addr() & (*iter)->get_netmask())) { //found a match in routing table
						if(((*iter)->get_netmask() | longest_prefix) != longest_prefix){
							longest_prefix = (*iter)->get_netmask(); // this is the longest prefix match
							correct_src = (*iter)->get_local_addr();
						}
					}
					iter++;
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
						net_dev_lst_t* nd_lst = g_p_net_device_table_mgr->get_net_device_val_lst_from_index(p_val->get_if_index());
						if (nd_lst) {
							net_dev_lst_t::iterator iter = nd_lst->begin();
							while (iter != nd_lst->end()) {
								if(p_val->get_gw_addr() == (*iter)->get_local_addr()) {
									p_val->set_gw(0);
									p_val->set_src_addr((*iter)->get_local_addr());
									break;
								}
								iter++;
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
			rt_mgr_logwarn("could not figure out source ip for gw address. rtv = %s", p_val->to_str());
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
}

bool route_table_mgr::parse_enrty(nlmsghdr *nl_header, route_val *p_val)
{
	int len;
	struct rtmsg *rt_msg;
	struct rtattr *rt_attribute;

	// get route entry header
	rt_msg = (struct rtmsg *) NLMSG_DATA(nl_header);

	// we are not concerned about the local and default route table
	if (rt_msg->rtm_family != AF_INET || rt_msg->rtm_table == RT_TABLE_LOCAL || rt_msg->rtm_table == RT_TABLE_DEFAULT)
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
		char if_name[IF_NAMESIZE];
		if_indextoname(p_val->get_if_index(),if_name);
		p_val->set_if_name(if_name);
		break;
	case RTA_SRC:
	case RTA_PREFSRC:
		p_val->set_src_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	default:
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

bool route_table_mgr::route_resolve(IN in_addr_t dst, unsigned char table_id, OUT in_addr_t *p_src, OUT in_addr_t *p_gw /*NULL*/)
{
	ip_address dst_addr = dst;
	rt_mgr_logdbg("dst addr '%s'", dst_addr.to_str().c_str());

	route_val *p_val = NULL;
	auto_unlocker lock(m_lock);
	if (find_route_val(dst, table_id, p_val)) {
		if (p_src) {
			*p_src = p_val->get_src_addr();
			rt_mgr_logdbg("dst ip '%s' resolved to src addr '%d.%d.%d.%d'", dst_addr.to_str().c_str(), NIPQUAD(*p_src));
		}
		if (p_gw) {
			*p_gw = p_val->get_gw_addr();
			rt_mgr_logdbg("dst ip '%s' resolved to gw addr '%d.%d.%d.%d'", dst_addr.to_str().c_str(), NIPQUAD(*p_gw));
		}
		return true;
	}
	return false;
}

void route_table_mgr::update_entry(INOUT route_entry* p_ent, bool b_register_to_net_dev /*= false*/)
{
	rt_mgr_logdbg("entry [%p]", p_ent);
	auto_unlocker lock(m_lock);
	if (p_ent && !p_ent->is_valid()) { //if entry is found in the collection and is not valid
		rt_mgr_logdbg("route_entry is not valid-> update value");
		route_val* p_val = NULL;
		in_addr_t peer_ip = p_ent->get_key().get_in_addr();
		unsigned char table_id = p_ent->get_key().get_table_id();

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
		} else {
			rt_mgr_logdbg("ERROR: could not find route val for route_entry '%s'", p_ent->to_str().c_str());
		}
	}
}

//code coverage
#if 0
void route_table_mgr::get_default_gw(in_addr_t *p_gw_ip, int *p_if_index)
{
	rt_mgr_logdbg("");
	auto_unlocker lock(m_lock);

	for (int i = 0; i < m_tab.entries_num; i++) {
		route_val *p_val = &(m_tab.value[i]);
		if (p_val->get_gw_addr() &&
		    p_val->get_type() == RTN_UNICAST &&
		    p_val->get_dst_addr() == INADDR_ANY &&
		    p_val->get_dst_pref_len() == 0) {
			rt_mgr_logdbg("detected default gateway %s, index: %d", p_val->get_if_name(), p_val->get_if_index());
			*p_if_index = p_val->get_if_index();
			*p_gw_ip = p_val->get_gw_addr();
			return;
		}
	}
}
#endif

route_entry* route_table_mgr::create_new_entry(route_table_key key, const observer *obs)
{
	// no need for lock - lock is activated in cache_collection_mgr::register_observer

	rt_mgr_logdbg("");
	NOT_IN_USE(obs);
	route_entry* p_ent = new route_entry(key);
	update_entry(p_ent, true);
	rt_mgr_logdbg("new entry %p created successfully", p_ent);
	return p_ent;
}

//code coverage
#if 0
route_val* route_table_mgr::find_route_val(route_val &netlink_route_val)
{
	in_addr_t dst_addr = netlink_route_val.get_dst_addr();
	int dst_prefix_len = netlink_route_val.get_dst_pref_len();
	int if_index = netlink_route_val.get_if_index();
	unsigned char table_id = netlink_route_val.get_table_id();
	for (int i = 0; i < m_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_tab.value[i];
		if (!p_val_from_tbl->is_deleted() && p_val_from_tbl->is_if_up()) {
			if (p_val_from_tbl->get_table_id() == table_id) {
				if(p_val_from_tbl->get_dst_addr() == dst_addr && p_val_from_tbl->get_dst_pref_len() == dst_prefix_len && p_val_from_tbl->get_if_index() == if_index) {
					return p_val_from_tbl;
				}
			}
		}
	}
	return NULL;
}

void route_table_mgr::addr_change_event(int if_index)
{
	for (int i = 0; i < m_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_tab.value[i];
		if (! p_val_from_tbl->is_deleted() && p_val_from_tbl->get_if_index() == if_index) {
			p_val_from_tbl->set_state(false);
			rt_mgr_logdbg("route_val %p is not valid", p_val_from_tbl);
		}
	}
}

void route_table_mgr::create_route_val_from_info(const netlink_route_info *netlink_route_info, route_val &netlink_route_val)
{
	char dst_addr_chr[ADDR_LEN];
	inet_ntop(AF_INET, netlink_route_info->dst_addr, dst_addr_chr, ADDR_LEN);
	netlink_route_val.set_dst_addr(inet_addr((const char*)dst_addr_chr));

	in_addr_t dst_mask = htonl(VMA_NETMASK(netlink_route_info->dst_prefixlen));
	netlink_route_val.set_dst_mask(dst_mask);
	netlink_route_val.set_dst_pref_len(netlink_route_info->dst_prefixlen);

	netlink_route_val.set_protocol(netlink_route_info->protocol);
	netlink_route_val.set_scope(netlink_route_info->scope);
	netlink_route_val.set_type(netlink_route_info->type);

	int if_index = netlink_route_info->oif;
	netlink_route_val.set_if_index(if_index);

	char if_name[IF_NAMESIZE];
	if_indextoname(if_index,if_name);
	netlink_route_val.set_if_name(if_name);

	struct sockaddr_in src_addr;
	if (!get_ipv4_from_ifname(if_name, &src_addr)) {
		netlink_route_val.set_src_addr(src_addr.sin_addr.s_addr);
	}

	netlink_route_val.set_str();
	if (g_vlogger_level >= VLOG_FUNC) {
		netlink_route_val.print_route_val();
	}
}
#endif

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

void route_table_mgr::update_invalid_entries()
{
	route_entry *p_ent;
	std::tr1::unordered_map<route_table_key, cache_entry_subject<route_table_key, route_val*> *>::iterator cache_itr;
	for (cache_itr = m_cache_tbl.begin(); cache_itr != m_cache_tbl.end(); cache_itr++) {
		p_ent = (route_entry *)cache_itr->second;
		if(!p_ent->is_valid()) {
			update_entry(p_ent);
		}
	}
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

//code coverage
#if 0
void route_table_mgr::del_route_event(route_val &netlink_route_val)
{
	in_addr_t del_dst_addr = netlink_route_val.get_dst_addr();
	in_addr_t del_dst_mask = netlink_route_val.get_dst_mask();
	char *del_if_name = (char *) netlink_route_val.get_if_name();

	rt_mgr_logdbg("netlink event- route deleted: dst '%d.%d.%d.%d', netmask '%d.%d.%d.%d', interface '%s'", NIPQUAD(del_dst_addr), NIPQUAD(del_dst_mask), del_if_name);

	route_val* p_val_from_tbl = find_route_val(netlink_route_val);
	if(p_val_from_tbl) {
		rt_mgr_logdbg("found deleted route val[%p]: %s", p_val_from_tbl, p_val_from_tbl->to_str());
		p_val_from_tbl->set_deleted();
		p_val_from_tbl->set_state(false);
		return;
	}
	rt_mgr_logdbg("route does not exist!");

	if (g_vlogger_level >= VLOG_FUNC) {
		print_route_tbl();
	}
	update_invalid_entries();
}
#endif

//code coverage
#if 0
void route_table_mgr::new_route_event(route_val &netlink_route_val)
{
	int number_of_entries = m_tab.entries_num++;
	netlink_route_val.set_state(true);

	in_addr_t new_dst_addr = netlink_route_val.get_dst_addr();
	in_addr_t new_dst_mask = netlink_route_val.get_dst_mask();
	int new_dst_pref_len = netlink_route_val.get_dst_pref_len();
	char *new_if_name = (char *) netlink_route_val.get_if_name();

	rt_mgr_logdbg("netlink event- route added: dst '%d.%d.%d.%d', netmask '%d.%d.%d.%d', interface '%s'", NIPQUAD(new_dst_addr), NIPQUAD(new_dst_mask), new_if_name);

	if(find_route_val(netlink_route_val)) {
		rt_mgr_logdbg("route already exists: dst '%d.%d.%d.%d', netmask '%d.%d.%d.%d', interface '%s'", NIPQUAD(new_dst_addr), NIPQUAD(new_dst_mask), new_if_name);
		return;
	}

	m_tab.value[number_of_entries] = netlink_route_val;
	in_addr_t common_prefix;
	// set necessary route_vals as not valid
	for (int i = 0; i < m_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_tab.value[i];
		if (!p_val_from_tbl->is_deleted() && p_val_from_tbl->is_if_up()) {
			common_prefix = p_val_from_tbl->get_dst_addr() & new_dst_mask;
			// check if the new route is more specific than an existing route
			// example: if route table contains entry for- 1.1.1.1/24
			//			and a new entry for- 1.1.1.1/32 is added
			// then route might change for some dst ips ---> set as invalid
			if((common_prefix == (new_dst_addr & new_dst_mask)) && p_val_from_tbl->get_dst_pref_len() < new_dst_pref_len) {
				p_val_from_tbl->set_state(false);
				rt_mgr_logdbg("route_val %p is not valid", p_val_from_tbl);
				p_val_from_tbl->print_route_val();
			}
		}
	}

	rt_mgr_logdbg("route added: dst '%d.%d.%d.%d', netmask '%d.%d.%d.%d', interface '%s'", NIPQUAD(new_dst_addr), NIPQUAD(new_dst_mask), new_if_name);

	if (g_vlogger_level >= VLOG_FUNC) {
		print_route_tbl();
	}
	update_invalid_entries();
}
#endif

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
bool inline is_route_event(uint16_t event_type)
{
	return (event_type == RTM_NEWROUTE || event_type == RTM_DELROUTE);
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void route_table_mgr::notify_cb(event *ev)
{
	NOT_IN_USE(ev); //TODO remove
#if 0
	route_nl_event *route_netlink_ev = dynamic_cast <route_nl_event*>(ev);
	const netlink_route_info *netlink_route_info = route_netlink_ev->get_route_info();
	uint16_t event_type = route_netlink_ev->nl_type;

	if(! is_route_event(event_type))
		return;

	rt_mgr_logdbg("received route event from netlink");
	route_val netlink_route_val;
	create_route_val_from_info(netlink_route_info, netlink_route_val);

	switch(event_type)
	{
	case RTM_DELROUTE:
		del_route_event(netlink_route_val);
		break;
	case RTM_NEWROUTE:
		new_route_event(netlink_route_val);
		break;
	}
#endif
}
