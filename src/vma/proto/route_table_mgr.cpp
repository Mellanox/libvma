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

#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((uint8_t *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

route_table_mgr* g_p_route_table_mgr = NULL;

route_table_mgr::route_table_mgr() : cache_table_mgr<ip_address,route_val*>("route_table_mgr")
{
	rt_mgr_logdbg("");

	m_pid = getpid();
	m_buff_size = MSG_BUFF_SIZE;
	m_seq_num = 0;

	// Create Socket
	BULLSEYE_EXCLUDE_BLOCK_START
	if ((m_fd = orig_os_api.socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
		rt_mgr_logerr("NL socket Creation: ");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	//save the routing table
	rt_mgr_update_tbl();

	// create route_entry for each net_dev- needed for receiving port up/down events for net_dev_entry
	route_val *p_rtv;
	for (int i = 0; i < m_rt_tab.entries_num; i++)
	{
		p_rtv = &m_rt_tab.rtv[i];
		in_addr_t src_addr = p_rtv->get_src_addr();
		std::tr1::unordered_map<in_addr_t, route_entry*>::iterator iter = m_rte_list_for_each_net_dev.find(src_addr);
		// if src_addr of interface exists in the map, no need to create another route_entry
		if (iter == m_rte_list_for_each_net_dev.end()) {
			m_rte_list_for_each_net_dev.insert(pair<in_addr_t, route_entry*> (src_addr, create_new_entry(ip_address(src_addr), NULL)));
		}
	}

	print_route_tbl();

	// register to netlink event
	g_p_netlink_handler->register_event(nlgrpROUTE, this);
	rt_mgr_logdbg("Registered to g_p_netlink_handler");

	rt_mgr_logdbg("Done");
}

route_table_mgr::~route_table_mgr()
{
	rt_mgr_logdbg("");
	if (m_fd) {
		orig_os_api.close(m_fd);
		m_fd = -1;
	}

	// clear all route_entrys created in the constructor
	std::tr1::unordered_map<in_addr_t, route_entry*>::iterator iter;
	for (iter = m_rte_list_for_each_net_dev.begin(); iter != m_rte_list_for_each_net_dev.end(); iter++) {
		route_entry* p_rte = iter->second;
		delete(p_rte);
	}

	rt_mgr_logdbg("Done");
}

void route_table_mgr::print_route_tbl()
{
	route_val *p_rtv;
	rt_mgr_logdbg("");
	for (int i = 0; i < m_rt_tab.entries_num; i++)
	{
		p_rtv = &m_rt_tab.rtv[i];
		p_rtv->print_route_val();
	}
}

void route_table_mgr::rt_mgr_update_tbl()
{
	struct nlmsghdr *nl_msg = NULL;
	int counter = 0;
	int len = 0;

	auto_unlocker lock(m_lock);
	m_rt_tab.entries_num = 0;

	rt_req_info_t req_info;
	memset(&req_info, 0, sizeof(req_info));
	rt_mgr_build_request(RT_TYPE_DUMP_RT, &req_info, &nl_msg);

	if (!rt_mgr_query(nl_msg, len))
		return;

	rt_mgr_parse_tbl(len, &counter);
	m_rt_tab.entries_num = counter;

	return;
}

void route_table_mgr::rt_mgr_build_request(rt_req_type_t type, rt_req_info_t *req_info, struct nlmsghdr **nl_msg)
{
	struct rtmsg *rt_msg;

	memset(m_msg_buf, 0, m_buff_size);

	// point the header and the msg structure pointers into the buffer
	*nl_msg = (struct nlmsghdr *)m_msg_buf;
	rt_msg = (struct rtmsg *)NLMSG_DATA(*nl_msg);

	//Fill in the nlmsg header
	(*nl_msg)->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	(*nl_msg)->nlmsg_seq = m_seq_num++;
	(*nl_msg)->nlmsg_pid = m_pid;
	rt_msg->rtm_family = AF_INET;

	switch (type) {
		case RT_TYPE_GET_RT:
			(*nl_msg)->nlmsg_type = RTM_GETROUTE;
			(*nl_msg)->nlmsg_flags = NLM_F_REQUEST;
			if (req_info->dst.s_addr && req_info->dst_pref_len) {
				rt_mgr_add_attr(*nl_msg,  m_buff_size, RTA_DST, &req_info->dst, req_info->dst_pref_len);
			}
			if (req_info->src.s_addr && req_info->src_pref_len) {
				rt_mgr_add_attr(*nl_msg,  m_buff_size, RTA_SRC, &req_info->src, req_info->src_pref_len);
			}
			break;
		case RT_TYPE_DUMP_RT:
			(*nl_msg)->nlmsg_type = RTM_GETROUTE;
			(*nl_msg)->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
			break;
		BULLSEYE_EXCLUDE_BLOCK_START
		default:
			rt_mgr_logwarn("Unknown netlink route request type.");
			break;
		BULLSEYE_EXCLUDE_BLOCK_END
	}
}

int route_table_mgr::rt_mgr_add_attr(struct nlmsghdr *nls_msghdr, uint32_t maxlen, int type, const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (NLMSG_ALIGN(nls_msghdr->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		rt_mgr_logerr("ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	rta = NLMSG_TAIL(nls_msghdr);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	nls_msghdr->nlmsg_len = NLMSG_ALIGN(nls_msghdr->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

bool route_table_mgr::rt_mgr_query(struct nlmsghdr *&nl_msg, int &len)
{
	if(m_fd < 0)
		return false;

	BULLSEYE_EXCLUDE_BLOCK_START
	if(orig_os_api.send(m_fd, nl_msg, nl_msg->nlmsg_len, 0) < 0){
		rt_mgr_logerr("Write To Socket Failed...\n");
		return false;
	}
	if((len = rt_mgr_recv_info()) < 0) {
		rt_mgr_logerr("Read From Socket Failed...\n");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return true;
}

int route_table_mgr::rt_mgr_recv_info()
{
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

	char *buf_ptr = m_msg_buf;

	do{
		//Receive response from the kernel
		BULLSEYE_EXCLUDE_BLOCK_START
		if((readLen = orig_os_api.recv(m_fd, buf_ptr, MSG_BUFF_SIZE - msgLen, 0)) < 0){
			rt_mgr_logerr("SOCK READ: ");
			return -1;
		}

		nlHdr = (struct nlmsghdr *)buf_ptr;

		//Check if the header is valid
		if((NLMSG_OK(nlHdr, (u_int)readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
		{
			rt_mgr_logerr("Error in received packet, readLen = %d, msgLen = %d, type=%d, bufLen = %d", readLen, nlHdr->nlmsg_len, nlHdr->nlmsg_type, MSG_BUFF_SIZE);
			if (nlHdr->nlmsg_len == MSG_BUFF_SIZE) {
				rt_mgr_logerr("The buffer we pass to netlink is too small for reading the whole routing table");
			}
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		//Check if the its the last message
		if(nlHdr->nlmsg_type == NLMSG_DONE) {
			break;
		}
		else{
			buf_ptr += readLen;
			msgLen += readLen;
		}

		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			break;
		}
	} while((nlHdr->nlmsg_seq != m_seq_num) || (nlHdr->nlmsg_pid != m_pid));
	return msgLen;
}

void route_table_mgr::rt_mgr_parse_tbl(int len, int *p_rte_counter)
{
	struct nlmsghdr *nl_header;
	int entry_cnt = 0;

	nl_header = (struct nlmsghdr *) m_msg_buf;
	for(;NLMSG_OK(nl_header, (u_int)len) && entry_cnt < MAX_RT_SIZE; nl_header = NLMSG_NEXT(nl_header, len))
	{
		if (rt_mgr_parse_enrty(nl_header, &m_rt_tab.rtv[entry_cnt])) {
			entry_cnt++;
		}
	}
	if (p_rte_counter)
		*p_rte_counter = entry_cnt;
}

bool route_table_mgr::rt_mgr_parse_enrty(nlmsghdr *nl_header, route_val *p_rtv)
{
	int len;
	struct rtmsg *rt_msg;
	struct rtattr *rt_attribute;

	// get route entry header
	rt_msg = (struct rtmsg *) NLMSG_DATA(nl_header);

	// we are only concerned about the main route table
	if (rt_msg->rtm_family != AF_INET || rt_msg->rtm_table != RT_TABLE_MAIN)
		return false;

	p_rtv->set_protocol(rt_msg->rtm_protocol);
	p_rtv->set_scope(rt_msg->rtm_scope);
	p_rtv->set_type(rt_msg->rtm_type);

	in_addr_t dst_mask = htonl(VMA_NETMASK(rt_msg->rtm_dst_len));
	p_rtv->set_dst_mask(dst_mask);
	p_rtv->set_dst_pref_len(rt_msg->rtm_dst_len);

	len = RTM_PAYLOAD(nl_header);
	rt_attribute = (struct rtattr *) RTM_RTA(rt_msg);

	for (;RTA_OK(rt_attribute, len);rt_attribute=RTA_NEXT(rt_attribute,len)) {
		rt_mgr_parse_attr(rt_attribute, p_rtv);
	}
	p_rtv->set_state(true);

	if (!p_rtv->get_src_addr()) {
		struct sockaddr_in src_addr;
		char *if_name = (char *)p_rtv->get_if_name();
		if (!get_ipv4_from_ifname(if_name, &src_addr)) {
			p_rtv->set_src_addr(src_addr.sin_addr.s_addr);
		}
		else {
			// Failed mapping if_name to IPv4 address
			// Should we log or return error also from here?
		}
	}

	p_rtv->set_str();
	return true;
}

void route_table_mgr::rt_mgr_parse_attr(struct rtattr *rt_attribute, route_val *p_rtv)
{
	switch (rt_attribute->rta_type) {
	case RTA_DST:
		p_rtv->set_dst_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	// next hop IPv4 address
	case RTA_GATEWAY:
		p_rtv->set_gw(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	// unique ID associated with the network interface
	case RTA_OIF:
		p_rtv->set_if_index(*(int *)RTA_DATA(rt_attribute));
		char if_name[IF_NAMESIZE];
		if_indextoname(p_rtv->get_if_index(),if_name);
		p_rtv->set_if_name(if_name);
		break;
	case RTA_SRC:
	case RTA_PREFSRC:
		p_rtv->set_src_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	default:
		break;
	}
}

bool route_table_mgr::find_route_val(in_addr_t &dst, route_val* &p_rtv)
{
	ip_address dst_addr = dst;
	rt_mgr_logfunc("dst addr '%s'", dst_addr.to_str().c_str());

	route_val *correct_route_val = NULL;
	int longest_prefix = -1;

	for (int i = 0; i < m_rt_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_rt_tab.rtv[i];
		if (!p_val_from_tbl->is_deleted() && p_val_from_tbl->is_if_up()) { // value was not deleted
			if(p_val_from_tbl->get_dst_addr() == (dst & p_val_from_tbl->get_dst_mask())) { //found a match in routing table
				if(p_val_from_tbl->get_dst_pref_len() > longest_prefix) { // this is the longest prefix match
					longest_prefix = p_val_from_tbl->get_dst_pref_len();
					correct_route_val = p_val_from_tbl;
				}
			}
		}
	}
	if (correct_route_val) {
		ip_address dst_gw = correct_route_val->get_dst_addr();
		p_rtv = correct_route_val;
		rt_mgr_logdbg("found route val[%p]: %s", p_rtv, p_rtv->to_str());
		return true;
	}

	rt_mgr_logdbg("destination gw wasn't found");
	return false;
}

bool route_table_mgr::route_resolve(IN in_addr_t dst, OUT in_addr_t *p_src, OUT in_addr_t *p_gw /*NULL*/)
{
	ip_address dst_addr = dst;
	rt_mgr_logdbg("dst addr '%s'", dst_addr.to_str().c_str());

	route_val *p_rtv = NULL;
	auto_unlocker lock(m_lock);
	if (find_route_val(dst, p_rtv)) {
		if (p_src) {
			*p_src = p_rtv->get_src_addr();
			rt_mgr_logdbg("dst ip '%s' resolved to src addr '%d.%d.%d.%d'", dst_addr.to_str().c_str(), NIPQUAD(*p_src));
		}
		if (p_gw) {
			*p_gw = p_rtv->get_gw_addr();
			rt_mgr_logdbg("dst ip '%s' resolved to gw addr '%d.%d.%d.%d'", dst_addr.to_str().c_str(), NIPQUAD(*p_gw));
		}
		return true;
	}
	return false;
}

void route_table_mgr::update_entry(INOUT route_entry* p_rte, bool b_register_to_net_dev /*= false*/)
{
	rt_mgr_logdbg("entry [%p]", p_rte);
	auto_unlocker lock(m_lock);
	if (p_rte && !p_rte->is_valid()) { //if entry is found in the collection and is not valid
		rt_mgr_logdbg("route_entry is not valid-> update value");
		route_val* p_rtv = NULL;
		in_addr_t peer_ip = p_rte->get_key().get_in_addr();
		if (find_route_val(peer_ip, p_rtv)) {
			p_rte->set_val(p_rtv);
			if (b_register_to_net_dev) {
				in_addr_t src_addr = p_rtv->get_src_addr();
				net_device_val* p_ndv = g_p_net_device_table_mgr->get_net_device_val(src_addr);
				// Check if broadcast IP which is NOT supported
				if (IS_BROADCAST_N(peer_ip)) {
					rt_mgr_logdbg("Disabling Offload for route_entry '%s' - this is BC address", p_rte->to_str().c_str());
					// Need to route traffic to/from OS
					// Prevent registering of net_device to route entry
				}
				// Check if: Local loopback over Ethernet case which is NOT supported yet
				else if (p_ndv && (p_ndv->get_transport_type() == VMA_TRANSPORT_ETH) &&  (peer_ip == src_addr)) {
					rt_mgr_logdbg("Disabling Offload for route_entry '%s' - this is an Ethernet unicast loopback route", p_rte->to_str().c_str());
					// Need to route traffic to/from OS
					// Prevent registering of net_device to route entry
				}
				else {
					// register to net device for bonding events
					p_rte->register_to_net_device();
				}
			}

			// All good, validate the new route entry
			p_rte->set_entry_valid();
		}
	}
}

//code coverage
#if 0
void route_table_mgr::get_default_gw(in_addr_t *p_gw_ip, int *p_if_index)
{
	rt_mgr_logdbg("");
	auto_unlocker lock(m_lock);

	for (int i = 0; i < m_rt_tab.entries_num; i++) {
		route_val *rtv = &(m_rt_tab.rtv[i]);
		if (rtv->get_gw_addr() &&
		    rtv->get_type() == RTN_UNICAST &&
		    rtv->get_dst_addr() == INADDR_ANY &&
		    rtv->get_dst_pref_len() == 0) {
			rt_mgr_logdbg("detected default gateway %s, index: %d", rtv->get_if_name(), rtv->get_if_index());
			*p_if_index = rtv->get_if_index();
			*p_gw_ip = rtv->get_gw_addr();
			return;
		}
	}
}
#endif

route_entry* route_table_mgr::create_new_entry(ip_address p_ip, const observer *obs)
{
	// no need for lock - lock is activated in cache_collection_mgr::register_observer

	rt_mgr_logdbg("");
	NOT_IN_USE(obs);
	route_entry* p_rte = new route_entry(p_ip);
	update_entry(p_rte, true);
	rt_mgr_logdbg("new entry %p created successfully", p_rte);
	return p_rte;
}

//code coverage
#if 0
route_val* route_table_mgr::find_route_val(route_val &netlink_route_val)
{
	in_addr_t dst_addr = netlink_route_val.get_dst_addr();
	int dst_prefix_len = netlink_route_val.get_dst_pref_len();
	int if_index = netlink_route_val.get_if_index();

	for (int i = 0; i < m_rt_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_rt_tab.rtv[i];
		if (!p_val_from_tbl->is_deleted() && p_val_from_tbl->is_if_up()) {
			if(p_val_from_tbl->get_dst_addr() == dst_addr && p_val_from_tbl->get_dst_pref_len() == dst_prefix_len && p_val_from_tbl->get_if_index() == if_index) {
				return p_val_from_tbl;
			}
		}
	}
	return NULL;
}

void route_table_mgr::addr_change_event(int if_index)
{
	for (int i = 0; i < m_rt_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_rt_tab.rtv[i];
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
	route_entry *p_rte;
	std::tr1::unordered_map<ip_address, cache_entry_subject<ip_address, route_val*> *>::iterator cache_itr;
	for (cache_itr = m_cache_tbl.begin(); cache_itr != m_cache_tbl.end(); cache_itr++) {
		p_rte = (route_entry *)cache_itr->second;
		if(!p_rte->is_valid()) {
			update_entry(p_rte);
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
	int number_of_entries = m_rt_tab.entries_num++;
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

	m_rt_tab.rtv[number_of_entries] = netlink_route_val;
	in_addr_t common_prefix;
	// set necessary route_vals as not valid
	for (int i = 0; i < m_rt_tab.entries_num; i++) {
		route_val* p_val_from_tbl = &m_rt_tab.rtv[i];
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
