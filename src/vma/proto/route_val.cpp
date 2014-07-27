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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>

#include "route_val.h"
#include "route_table_mgr.h"

#define MODULE_NAME 		"rtv"

#define rt_val_loginfo		__log_info_info
#define rt_val_logdbg		__log_info_dbg
#define rt_val_logfunc		__log_info_func

route_val::route_val(): cache_observer()
{
	m_dst_addr = 0;
	m_dst_mask = 0;
	m_dst_pref_len = 0;
	m_src_addr = 0;
	m_gw = 0;
	m_protocol = 0;
	m_scope = 0;
	m_type = 0;
	m_table_id	= 0;
	memset(m_if_name, 0, IF_NAMESIZE * sizeof(char));
	m_if_index = 0;
	m_is_valid = false;
	m_b_deleted = false;
	m_b_if_up = true;
	memset(m_str, 0, BUFF_SIZE * sizeof(char));
}

void route_val::set_str()
{
        strcpy(m_str, "dst:");

        if (m_dst_addr != 0)
                sprintf(m_str, "%s %-15s", m_str, inet_ntoa(*((in_addr *)&m_dst_addr)));
        else
                sprintf(m_str,"%s %-15s", m_str, "default");

        if (m_dst_mask != 0)
                sprintf(m_str, "%s netmask: %-15s", m_str, inet_ntoa(*((in_addr *)&m_dst_mask)));

        if (m_gw != 0)
                sprintf(m_str, "%s gw:      %-15s", m_str, inet_ntoa(*((in_addr *)&m_gw)));

        sprintf(m_str, "%s dev: %-5s", m_str, m_if_name);

        if (m_src_addr != 0)
                sprintf(m_str, "%s src: %-15s", m_str, inet_ntoa(*((in_addr *)&m_src_addr)));
        else
                sprintf(m_str, "%s                     ", m_str);
				
	if (m_table_id != RT_TABLE_MAIN)
		sprintf(m_str, "%s table :%-10u", m_str, m_table_id);
       	else
		sprintf(m_str, "%s table :%-10s", m_str, "main");		

        sprintf(m_str, "%s scope %3d type %2d index %2d", m_str, m_scope, m_type, m_if_index);

        if (m_b_deleted)
        	sprintf(m_str, "%s ---> DELETED", m_str);
}

void route_val::print_val()
{
	set_str();
	rt_val_logdbg("%s", to_str());
}
