/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef RULE_TABLE_MGR_H
#define RULE_TABLE_MGR_H

#include <unistd.h>
#include <bits/sockaddr.h>
#include <tr1/unordered_map>
#include "vma/infra/cache_subject_observer.h"
#include "vma/proto/netlink_socket_mgr.h"
#include "rule_entry.h"

/*
* This class manages routing rule related operation such as getting rules from kernel,
* finding table ID for given destination info and cashing usage history for rule table.
*/
class rule_table_mgr : public netlink_socket_mgr<rule_val>, public cache_table_mgr<rule_table_key, rule_val*> 
{
public:
	rule_table_mgr();
	
	rule_entry* 	create_new_entry(rule_table_key key, const observer *obs);
	void 	   	update_entry(rule_entry* p_ent);
	bool	 	rule_resolve(rule_table_key key, unsigned char *table_id);

protected:
	virtual bool	parse_enrty(nlmsghdr *nl_header, rule_val *p_val);
	virtual void	update_tbl();
	
private:

	void		parse_attr(struct rtattr *rt_attribute, rule_val *p_val);
	
	bool		find_rule_val(rule_table_key key, rule_val* &p_val);
	bool 		is_matching_rule(rule_table_key rrk, rule_val* p_val);
};

extern rule_table_mgr* g_p_rule_table_mgr;

#endif /* RULE_TABLE_MGR_H */
