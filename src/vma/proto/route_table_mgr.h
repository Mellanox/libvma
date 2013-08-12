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


#ifndef ROUTE_TABLE_MGR_H
#define ROUTE_TABLE_MGR_H

#include <unistd.h>
#include <bits/sockaddr.h>
#include <tr1/unordered_map>
#include "vma/infra/cache_subject_observer.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "route_entry.h"

#define MAX_RT_SIZE 255
#define MSG_BUFF_SIZE 81920
#define ADDR_LEN 46 // needs 16-bytes for IPv4, and 46-bytes for IPv6

// this structure represent a routing table
typedef struct
{
	route_val rtv[MAX_RT_SIZE];
	uint8_t entries_num;
} routing_table_t;

// routing query request information
typedef struct
{
	in_addr dst;
	uint8_t dst_pref_len;
	in_addr src;
	uint8_t src_pref_len;
} rt_req_info_t;

enum rt_req_type_t
{
	RT_TYPE_DUMP_RT,
	RT_TYPE_GET_RT
};

class route_table_mgr : public cache_table_mgr<ip_address,route_val*>, public observer
{
public:
	route_table_mgr();
	virtual ~route_table_mgr();

	void		get_default_gw(in_addr_t *p_gw_ip, int *p_if_index);
	bool		route_resolve(IN in_addr_t dst, OUT in_addr_t *p_src, OUT in_addr_t *p_gw = NULL);

	route_entry* 	create_new_entry(ip_address p_ip, const observer *obs);
	void 		update_entry(INOUT route_entry* p_rte, bool b_register_to_net_dev = false);

	virtual void 	notify_cb(event *ev);
	void 		addr_change_event(int if_index);

private:
	routing_table_t m_rt_tab; // main routing table

	int 		m_fd; // netlink socket to communicate with the kernel
	uint32_t 	m_pid; // process pid
	uint32_t 	m_seq_num; // seq num of the netlink messages
	char 		m_msg_buf[MSG_BUFF_SIZE]; // we use this buffer for sending/receiving netlink messages
	uint32_t 	m_buff_size;

	// in constructor creates route_entry for each net_dev, to receive events in case there are no other route_entrys
	std::tr1::unordered_map<in_addr_t, route_entry*> m_rte_list_for_each_net_dev;

	bool		find_route_val(in_addr_t &dst_addr, route_val* &p_rtv);

	// save current main rt table
	void		rt_mgr_update_tbl();
	void		rt_mgr_build_request(rt_req_type_t type, rt_req_info_t *req_info, struct nlmsghdr **nl_msg);
	int 		rt_mgr_add_attr(struct nlmsghdr *nls_msghdr, uint32_t maxlen, int type, const void *data, int alen);
	bool		rt_mgr_query(struct nlmsghdr *&nl_msg, int &len);
	int		rt_mgr_recv_info();
	void		rt_mgr_parse_tbl(int len, int *rt_entry_num = NULL);
	bool		rt_mgr_parse_enrty(nlmsghdr *nl_header, route_val *p_rtv);
	void		rt_mgr_parse_attr(struct rtattr *rt_attribute, route_val *p_rtv);

	void 		update_invalid_entries();
	void 		delete_rt_entry_val(route_val *p_rtv);
	void 		add_rt_entry_val(route_val *p_rtv);

	void		print_route_tbl();

	void 		create_route_val_from_info(const netlink_route_info *netlink_route_info, route_val &netlink_route_val);
	void 		del_route_event(route_val &netlink_route_val);
	void 		new_route_event(route_val &netlink_route_val);
	route_val* 	find_route_val(route_val &netlink_route_val);
};

extern route_table_mgr* g_p_route_table_mgr;

#endif /* ROUTE_TABLE_MGR_H */
