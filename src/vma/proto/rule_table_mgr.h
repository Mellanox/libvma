/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef RULE_TABLE_MGR_H
#define RULE_TABLE_MGR_H

#include <unistd.h>
#include <bits/sockaddr.h>
#include "vma/infra/cache_subject_observer.h"
#include "vma/proto/netlink_socket_mgr.h"
#include "rule_entry.h"

/*
* This class manages routing rule related operation such as getting rules from kernel,
* finding table ID for given destination info and cashing usage history for rule table.
*/
class rule_table_mgr : public netlink_socket_mgr<rule_val>, public cache_table_mgr<route_rule_table_key, std::deque<rule_val*>*> 
{
public:
	rule_table_mgr();
	
	rule_entry* 	create_new_entry(route_rule_table_key key, const observer *obs);
	void 	   	update_entry(rule_entry* p_ent);
	bool	 	rule_resolve(route_rule_table_key key, std::deque<uint32_t> &table_id_list);

protected:
	virtual bool	parse_entry(struct nl_object *nl_obj, void *p_val_context);
	virtual void	update_tbl();
	
private:

	void		parse_attr(struct rtnl_rule *rule, rule_val *p_val);
	
	bool		find_rule_val(route_rule_table_key key, std::deque<rule_val*>* &p_val);
	bool 		is_matching_rule(route_rule_table_key rrk, rule_val* p_val);
};

extern rule_table_mgr* g_p_rule_table_mgr;

#endif /* RULE_TABLE_MGR_H */
