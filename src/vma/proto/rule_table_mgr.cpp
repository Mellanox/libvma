/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <linux/fib_rules.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "utils/bullseye.h"
#include "utils/lock_wrapper.h"
#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/utils.h"
#include "vma/util/if.h"
#include "rule_table_mgr.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/sock/sock-redirect.h"
#include "ip_address.h"

// debugging macros
#define MODULE_NAME 		"rrm:"

#define rr_mgr_if_logpanic	__log_panic
#define	rr_mgr_logerr		__log_err
#define rr_mgr_logwarn		__log_warn
#define rr_mgr_loginfo		__log_info
#define rr_mgr_logdbg		__log_dbg
#define rr_mgr_logfunc		__log_func
#define rr_mgr_logfuncall	__log_funcall
	
rule_table_mgr* g_p_rule_table_mgr = NULL;

rule_table_mgr::rule_table_mgr() : netlink_socket_mgr<rule_val>(RULE_DATA_TYPE), cache_table_mgr<route_rule_table_key, std::deque<rule_val*>*>("rule_table_mgr")
{

	rr_mgr_logdbg("");

	//Read Rule table from kernel and save it in local variable. 
	update_tbl();
	
	//Print table
	print_val_tbl();
	
	rr_mgr_logdbg("Done");
}

//This function uses Netlink to get routing rules saved in kernel then saved it locally.
void rule_table_mgr::update_tbl()
{
	auto_unlocker lock(m_lock);

	netlink_socket_mgr<rule_val>::update_tbl();

	return;
}

// Parse received rule entry into custom object (rule_val).
// Parameters:
//		nl_obj	    : object that contain rule entry.
//		p_val		: custom object that contain parsed rule data.
// return true if its not related to local or default table, false otherwise.
bool rule_table_mgr::parse_entry(struct nl_object *nl_obj, void *p_val_context)
{
	rule_val *p_val = static_cast<rule_val *>(p_val_context);
	// Cast the generic nl_object to a specific route or rule object
	struct rtnl_rule *rule = reinterpret_cast<struct rtnl_rule *>(nl_obj);

	uint32_t table_id = rtnl_rule_get_table(rule);
	if (rtnl_rule_get_family(rule) != AF_INET || table_id == RT_TABLE_LOCAL) {
		return false;
	}

	p_val->set_tos(rtnl_rule_get_dsfield(rule));
	p_val->set_table_id(table_id);

	parse_attr(rule, p_val);

	p_val->set_state(true);
	p_val->set_str();
	return true;
}

// Parse received rule attribute for given rule.
// Parameters:
//		rule	        : object that contain rule attribute.
//		p_val			: custom object that contain parsed rule data.
void rule_table_mgr::parse_attr(struct rtnl_rule *rule, rule_val *p_val)
{
	// FRA_PRIORITY: Rule Priority
	uint32_t priority = rtnl_rule_get_prio(rule);
	if (priority) {
		p_val->set_priority(priority);
	}

	// FRA_DST: Destination Address
	struct nl_addr *dst = rtnl_rule_get_dst(rule);
	if (dst) {
		p_val->set_dst_addr(*(in_addr_t *)nl_addr_get_binary_addr(dst));
	}

	// FRA_SRC: Source Address
	struct nl_addr *src = rtnl_rule_get_src(rule);
	if (src) {
		p_val->set_src_addr(*(in_addr_t *)nl_addr_get_binary_addr(src));
	}

	// FRA_IFNAME: Input Interface Name
	char *iif_name = rtnl_rule_get_iif(rule);
	if (iif_name) {
		p_val->set_iif_name(iif_name);
	}

	// FRA_TABLE: Table ID
	uint32_t table_id = rtnl_rule_get_table(rule);
	if (table_id) {
		p_val->set_table_id(table_id);
	}

#if DEFINED_FRA_OIFNAME
	// FRA_OIFNAME: Output Interface Name (if available)
	char *oif_name = rtnl_rule_get_oif(rule);
	if (oif_name) {
		p_val->set_oif_name(oif_name);
	}
#endif
}

// Create rule entry object for given destination key and fill it with matching rule value from rule table.
// Parameters: 
//		key		: key object that contain information about destination.
//		obs		: object that contain observer for specific rule entry.
//	Returns created rule entry object.
rule_entry* rule_table_mgr::create_new_entry(route_rule_table_key key, const observer *obs)
{
	rr_mgr_logdbg("");
	NOT_IN_USE(obs);
	rule_entry* p_ent = new rule_entry(key);
	update_entry(p_ent);
	rr_mgr_logdbg("new entry %p created successfully", p_ent);
	return p_ent;
}

// Update invalid rule entry with matching rule value from rule table.
// Parameters: 
//		p_ent		: rule entry that will be updated if it is invalid.
void rule_table_mgr::update_entry(rule_entry* p_ent)
{
	rr_mgr_logdbg("entry [%p]", p_ent);
	auto_unlocker lock(m_lock);
	
	if (p_ent && !p_ent->is_valid()) { //if entry is found in the collection and is not valid
		
		rr_mgr_logdbg("rule_entry is not valid-> update value");
		std::deque<rule_val*>* p_rrv;
		p_ent->get_val(p_rrv);
		/* p_rrv->clear(); TODO for future rule live updates */
		if (!find_rule_val(p_ent->get_key(), p_rrv)) {
			rr_mgr_logdbg("ERROR: could not find rule val for rule_entry '%s'", p_ent->to_str().c_str());
		}
	} 
}

// Find rule form rule table that match given destination info. 
// Parameters: 
//		key		: key object that contain information about destination.
//		p_val	: list of rule_val object that will contain information about all rule that match destination info    
// Returns true if at least one rule match destination info, false otherwise.
bool rule_table_mgr::find_rule_val(route_rule_table_key key, std::deque<rule_val*>* &p_val)
{
	rr_mgr_logfunc("destination info %s:", key.to_str().c_str());

	for (int index = 0; index < m_tab.entries_num; index++) {
		rule_val* p_val_from_tbl = &m_tab.value[index];
		if (p_val_from_tbl->is_valid() && is_matching_rule(key, p_val_from_tbl)) {
			p_val->push_back(p_val_from_tbl);
			rr_mgr_logdbg("found rule val[%p]: %s", p_val_from_tbl, p_val_from_tbl->to_str());
		}
	}

	return !p_val->empty();
}

// Check matching between given destination info. and specific rule from rule table. 
// Parameters: 
//		key		: key object that contain information about destination.
//		p_val	: rule_val object that contain information about specific rule from rule table   
// Returns true if destination info match rule value, false otherwise.
bool rule_table_mgr::is_matching_rule(route_rule_table_key key, rule_val* p_val)
{

	in_addr_t	m_dst_ip	= key.get_dst_ip();
	in_addr_t	m_src_ip	= key.get_src_ip();
	uint8_t		m_tos		= key.get_tos();
	
	in_addr_t	rule_dst_ip	= p_val->get_dst_addr();
	in_addr_t	rule_src_ip	= p_val->get_src_addr();
	uint8_t		rule_tos	= p_val->get_tos();
	char*		rule_iif_name	= (char *)p_val->get_iif_name();
	char*		rule_oif_name	= (char *)p_val->get_oif_name();
	
	bool is_match = false;
	
	// Only destination IP, source IP and TOS are checked with rule, since IIF and OIF is not filled in dst_entry object.
	if ((rule_dst_ip == 0) || (rule_dst_ip == m_dst_ip)) { // Check match in destination IP
	
		if ((rule_src_ip == 0) || (rule_src_ip == m_src_ip)) { // Check match in source IP
		
			if ((rule_tos == 0) || (rule_tos == m_tos)) { // Check match in TOS value
			
				if (strcmp(rule_iif_name, "") == 0) { // Check that rule doesn't contain IIF since we can't check match with
				
					if (strcmp(rule_oif_name, "") == 0) { // Check that rule doesn't contain OIF since we can't check match with
						is_match = true;
					}
				}
			}
		}
	}

	return is_match;
}

// Find table ID for given destination info.
// Parameters: 
//		key			: key object that contain information about destination.
//		table_id_list	: list that will contain table ID for all rule that match destination info   
// Returns true if at least one rule match destination info, false otherwise.
bool rule_table_mgr::rule_resolve(route_rule_table_key key, std::deque<uint32_t> &table_id_list)
{
	rr_mgr_logdbg("dst info: '%s'", key.to_str().c_str());

	std::deque<rule_val*> values;
	std::deque<rule_val*>* p_values = &values;
	auto_unlocker lock(m_lock);
	if (find_rule_val(key, p_values)) {
		for (std::deque<rule_val*>::iterator val = values.begin(); val != values.end(); val++) {
			table_id_list.push_back((*val)->get_table_id());
			rr_mgr_logdbg("dst info: '%s' resolved to table ID '%u'", key.to_str().c_str(), (*val)->get_table_id());
		}
	}
	
	return !table_id_list.empty();
}

