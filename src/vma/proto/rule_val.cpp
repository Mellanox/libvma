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
#include <string.h>
#include <stdlib.h>

#include "rule_val.h"
#include "rule_table_mgr.h"

#define MODULE_NAME 		"rrv"

#define rr_val_loginfo		__log_info_info
#define rr_val_logdbg		__log_info_dbg
#define rr_val_logfunc		__log_info_func

rule_val::rule_val(): cache_observer()
{
	m_protocol = 0;
	m_scope = 0;
	m_type = 0;
	m_dst_addr = 0;
	m_src_addr = 0;
	memset(m_oif_name, 0, IF_NAMESIZE * sizeof(char));
	memset(m_iif_name, 0, IF_NAMESIZE * sizeof(char));
	m_priority = 0;
	m_tos = 0;
	m_table_id = 0;
	m_is_valid = false;
	memset(m_str, 0, BUFF_SIZE * sizeof(char));
	
}

//This function build string that represent a row in the rule table.
void rule_val::set_str()
{

	sprintf(m_str, "Priority :%-10u", m_priority);

	if (m_src_addr != 0)
        	sprintf(m_str, "%s from :%-10s", m_str, inet_ntoa(*((in_addr *)&m_src_addr)));	

	if (m_dst_addr != 0)
        	sprintf(m_str, "%s to :%-12s", m_str, inet_ntoa(*((in_addr *)&m_dst_addr)));		

    	if (m_tos != 0)	
       		sprintf(m_str, "%s tos :%-11u", m_str, m_tos);

    	if (strcmp(m_iif_name, "") != 0)
		sprintf(m_str, "%s iif :%-11s", m_str, m_iif_name);

    	if (strcmp(m_oif_name, "") != 0)
		sprintf(m_str, "%s oif :%-11s", m_str, m_oif_name);		
		
   	if (m_table_id != RT_TABLE_MAIN)
		sprintf(m_str, "%s lookup table :%-10u", m_str, m_table_id);
	else
		sprintf(m_str, "%s lookup table :%-10s", m_str, "main");
		
}

//This function prints a string that represent a row in the rule table as debug log.
void rule_val::print_val()
{
	set_str();
	rr_val_logdbg("%s", to_str());
}
