/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
	m_dst_addr = 0;
	m_src_addr = 0;
	memset(m_oif_name, 0, IFNAMSIZ * sizeof(char));
	memset(m_iif_name, 0, IFNAMSIZ * sizeof(char));
	m_priority = 0;
	m_tos = 0;
	m_table_id = 0;
	m_is_valid = false;
	memset(m_str, 0, BUFF_SIZE * sizeof(char));
	
}

//This function build string that represent a row in the rule table.
void rule_val::set_str()
{
	char str_addr[INET_ADDRSTRLEN];
	char str_x[100] = {0};

	sprintf(m_str, "Priority :%-10u", m_priority);

	if (m_src_addr != 0) {
		inet_ntop(AF_INET, &m_src_addr_in_addr, str_addr, sizeof(str_addr));
		sprintf(str_x, " from :%-10s", str_addr);
	}
	strcat(m_str, str_x);

	str_x[0] = '\0';
	if (m_dst_addr != 0) {
		inet_ntop(AF_INET, &m_dst_addr_in_addr, str_addr, sizeof(str_addr));
		sprintf(str_x, " to :%-12s", str_addr);
	}
	strcat(m_str, str_x);

	str_x[0] = '\0';
    	if (m_tos != 0)	
       		sprintf(str_x, " tos :%-11u", m_tos);
	strcat(m_str, str_x);

	str_x[0] = '\0';
    	if (strcmp(m_iif_name, "") != 0)
		sprintf(str_x, " iif :%-11s", m_iif_name);
	strcat(m_str, str_x);

	str_x[0] = '\0';
    	if (strcmp(m_oif_name, "") != 0)
		sprintf(str_x, " oif :%-11s", m_oif_name);		
	strcat(m_str, str_x);

	str_x[0] = '\0';
   	if (m_table_id != RT_TABLE_MAIN)
		sprintf(str_x, " lookup table :%-10u", m_table_id);
	else
		sprintf(str_x, " lookup table :%-10s", "main");
	strcat(m_str, str_x);
}

//This function prints a string that represent a row in the rule table as debug log.
void rule_val::print_val()
{
	set_str();
	rr_val_logdbg("%s", to_str());
}
