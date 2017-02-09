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


#ifndef ROUTE_TABLE_MGR_H
#define ROUTE_TABLE_MGR_H

#include <unistd.h>
#include <bits/sockaddr.h>
#include <tr1/unordered_map>
#include "vma/infra/cache_subject_observer.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "rule_table_mgr.h"
#include "route_entry.h"

#define ADDR_LEN 46 // needs 16-bytes for IPv4, and 46-bytes for IPv6

class route_table_mgr : public netlink_socket_mgr<route_val>, public cache_table_mgr<route_rule_table_key, route_val*>, public observer
{
public:
	route_table_mgr();
	virtual ~route_table_mgr();

	void		get_default_gw(in_addr_t *p_gw_ip, int *p_if_index);
	bool		route_resolve(IN route_rule_table_key key, OUT in_addr_t *p_src, OUT in_addr_t *p_gw = NULL);

	route_entry* 	create_new_entry(route_rule_table_key key, const observer *obs);
	void 		update_entry(INOUT route_entry* p_ent, bool b_register_to_net_dev = false);

	virtual void 	notify_cb(event *ev);
	void 		addr_change_event(int if_index);

protected:
	virtual bool	parse_enrty(nlmsghdr *nl_header, route_val *p_val);

private:
	// in constructor creates route_entry for each net_dev, to receive events in case there are no other route_entrys
	std::tr1::unordered_map<in_addr_t, route_entry*> m_rte_list_for_each_net_dev;

	bool		find_route_val(in_addr_t &dst_addr, unsigned char table_id, route_val* &p_val);
	
	// save current main rt table
	void		update_tbl();
	void		parse_attr(struct rtattr *rt_attribute, route_val *p_val);
	
	void		rt_mgr_update_source_ip();

	void 		update_invalid_entries();
	void 		delete_rt_entry_val(route_val *p_val);
	void 		add_rt_entry_val(route_val *p_val);


	void 		del_route_event(route_val &netlink_route_val);
	void 		new_route_event(route_val* netlink_route_val);
	route_val* 	find_route_val(route_val &netlink_route_val);
};

extern route_table_mgr* g_p_route_table_mgr;

#endif /* ROUTE_TABLE_MGR_H */
