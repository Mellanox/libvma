/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef ROUTE_TABLE_MGR_H
#define ROUTE_TABLE_MGR_H

#include <unistd.h>
#include <bits/sockaddr.h>
#include <unordered_map>
#include "vma/infra/cache_subject_observer.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "rule_table_mgr.h"
#include "route_entry.h"

#define ADDR_LEN 46 // needs 16-bytes for IPv4, and 46-bytes for IPv6

typedef std::unordered_map<in_addr_t, route_entry*> in_addr_route_entry_map_t;
typedef std::unordered_map<route_rule_table_key, cache_entry_subject<route_rule_table_key, route_val*> *> rt_tbl_cach_entry_map_t;

struct route_result {
	in_addr_t	p_src;
	in_addr_t	p_gw;
	uint32_t	mtu;
	route_result(): p_src(0), p_gw(0) ,mtu(0) {}
};

class route_table_mgr : public netlink_socket_mgr<route_val>, public cache_table_mgr<route_rule_table_key, route_val*>, public observer
{
public:
	route_table_mgr();
	virtual ~route_table_mgr();

	bool		route_resolve(IN route_rule_table_key key, OUT route_result &res);

	route_entry* 	create_new_entry(route_rule_table_key key, const observer *obs);
	void 		update_entry(INOUT route_entry* p_ent, bool b_register_to_net_dev = false);

	virtual void 	notify_cb(event *ev);

protected:
	virtual bool	parse_entry(struct nl_object *nl_obj, void *p_val_context);

private:
	// in constructor creates route_entry for each net_dev, to receive events in case there are no other route_entrys
	in_addr_route_entry_map_t m_rte_list_for_each_net_dev;

	bool		find_route_val(in_addr_t &dst_addr, uint32_t table_id, route_val* &p_val);
	
	// save current main rt table
	void		update_tbl();
	void		parse_attr(struct rtnl_route *route, route_val *p_val);
	
	void		rt_mgr_update_source_ip();

	void 		new_route_event(route_val* netlink_route_val);
};

extern route_table_mgr* g_p_route_table_mgr;

#endif /* ROUTE_TABLE_MGR_H */
