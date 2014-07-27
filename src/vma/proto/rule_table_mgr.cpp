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
#include <net/if.h>

#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/utils.h"
#include "rule_table_mgr.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/sock/sock-redirect.h"
#include "lwip/ip_addr.h"
#include "ip_address.h"
#include "vma/util/bullseye.h"

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

rule_table_mgr::rule_table_mgr() : netlink_socket_mgr<rule_val>(RULE_DATA_TYPE), cache_table_mgr<rule_table_key, rule_val*>("rule_table_mgr")
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
//		nl_header	: object that contain rule entry.
//		p_val		: custom object that contain parsed rule data.
// return true if its not related to local or default table, false otherwise.
bool rule_table_mgr::parse_enrty(nlmsghdr *nl_header, rule_val *p_val)
{
	int len;
	struct rtmsg *rt_msg;
	struct rtattr *rt_attribute;

	// get rule entry header
	rt_msg = (struct rtmsg *) NLMSG_DATA(nl_header);

	// we are not concerned about the local and default rule table
	if (rt_msg->rtm_family != AF_INET || rt_msg->rtm_table == RT_TABLE_LOCAL || rt_msg->rtm_table == RT_TABLE_DEFAULT)
		return false;

	p_val->set_protocol(rt_msg->rtm_protocol);
	p_val->set_scope(rt_msg->rtm_scope);
	p_val->set_type(rt_msg->rtm_type);
	p_val->set_tos(rt_msg->rtm_tos);
	p_val->set_table_id(rt_msg->rtm_table);

	len = RTM_PAYLOAD(nl_header);
	rt_attribute = (struct rtattr *) RTM_RTA(rt_msg);

	for (;RTA_OK(rt_attribute, len);rt_attribute=RTA_NEXT(rt_attribute,len)) {
		parse_attr(rt_attribute, p_val);
	}
	p_val->set_state(true);
	p_val->set_str();
	return true;
}

// Parse received rule attribute for given rule.
// Parameters: 
//		rt_attribute	: object that contain rule attribute.
//		p_val			: custom object that contain parsed rule data.
void rule_table_mgr::parse_attr(struct rtattr *rt_attribute, rule_val *p_val)
{
	switch (rt_attribute->rta_type) {
		case RTA_PRIORITY:
			p_val->set_priority(*(uint32_t *)RTA_DATA(rt_attribute));
			break;			
		case RTA_DST:
			p_val->set_dst_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
			break;
		case RTA_SRC:
			p_val->set_src_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
			break;			
		case RTA_IIF:
			p_val->set_iif_name((char *)RTA_DATA(rt_attribute));
			break;	
		case RTA_OIF:
			p_val->set_oif_name((char *)RTA_DATA(rt_attribute));
			break;				
		default:
			break;
	}
}


// Create rule entry object for given destination key and fill it with matching rule value from rule table.
// Parameters: 
//		key		: key object that contain information about destination.
//		obs		: object that contain observer for specific rule entry.
//	Returns created rule entry object.
rule_entry* rule_table_mgr::create_new_entry(rule_table_key key, const observer *obs)
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
		rule_val* p_rrv = NULL;
		
		if (find_rule_val(p_ent->get_key(), p_rrv)) {
			p_ent->set_val(p_rrv);
			// All good, validate the new rule entry
			p_ent->set_entry_valid();
		}
		else {
			rr_mgr_logdbg("ERROR: could not find rule val for rule_entry '%s'", p_ent->to_str().c_str());
		}
	} 
}

// Find rule form rule table that match given destination info. 
// Parameters: 
//		key		: key object that contain information about destination.
//		p_val	: rule_val object that will contain information about first rule that match destination info    
// Returns true if at least one rule match destination info, false otherwise.
bool rule_table_mgr::find_rule_val(rule_table_key key, rule_val* &p_val)
{
	rr_mgr_logfunc("destination info :", key.to_str().c_str());

	for (int index = 0; index < m_tab.entries_num; index++) {
		rule_val* p_val_from_tbl = &m_tab.value[index];
		if (is_matching_rule(key, p_val_from_tbl)) {
		p_val = p_val_from_tbl;
		rr_mgr_logdbg("found rule val[%p]: %s", p_val, p_val->to_str());
		return true;
		}
	}

	return false;
}

// Check matching between given destination info. and specific rule from rule table. 
// Parameters: 
//		key		: key object that contain information about destination.
//		p_val	: rule_val object that contain information about specific rule from rule table   
// Returns true if destination info match rule value, false otherwise.
bool rule_table_mgr::is_matching_rule(rule_table_key key, rule_val* p_val)
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
//		table_id	: object that will contain table ID for first rule that match destination info   
// Returns true if at least one rule match destination info, false otherwise.
bool rule_table_mgr::rule_resolve(rule_table_key key, unsigned char *table_id)
{
	rr_mgr_logdbg("dst info: '%s'", key.to_str().c_str());

	rule_val *p_val = NULL;
	auto_unlocker lock(m_lock);
	if (find_rule_val(key, p_val)) {
		*table_id = p_val->get_table_id();
		rr_mgr_logdbg("dst info: '%s' resolved to table ID '%u'", key.to_str().c_str(), (*table_id));
		return true;
	}
	
	return false;
}

