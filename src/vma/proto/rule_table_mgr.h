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
	bool	 	rule_resolve(route_rule_table_key key, std::deque<unsigned char> &table_id_list);

protected:
	virtual bool	parse_enrty(nlmsghdr *nl_header, rule_val *p_val);
	virtual void	update_tbl();
	
private:

	void		parse_attr(struct rtattr *rt_attribute, rule_val *p_val);
	
	bool		find_rule_val(route_rule_table_key key, std::deque<rule_val*>* &p_val);
	bool 		is_matching_rule(route_rule_table_key rrk, rule_val* p_val);
};

extern rule_table_mgr* g_p_rule_table_mgr;

#endif /* RULE_TABLE_MGR_H */
