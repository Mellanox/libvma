/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "vma/util/if.h"

#include "route_val.h"
#include "route_table_mgr.h"
#include "vma/dev/net_device_table_mgr.h"

#define MODULE_NAME 		"rtv"

#define rt_val_loginfo		__log_info_info
#define rt_val_logdbg		__log_info_dbg
#define rt_val_logfunc		__log_info_func

route_val::route_val()
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
	memset(m_if_name, 0, IFNAMSIZ * sizeof(char));
	m_if_index = 0;
	m_is_valid = false;
	m_b_deleted = false;
	m_b_if_up = true;
	m_mtu = 0;
	memset(m_str, 0, BUFF_SIZE * sizeof(char));
}

void route_val::set_str()
{
	char str_addr[INET_ADDRSTRLEN];
	char str_x[100] = {0};

	strcpy(m_str, "dst:");

	str_x[0] = '\0';
	if (m_dst_addr != 0) {
		inet_ntop(AF_INET, &m_dst_addr_in_addr, str_addr, sizeof(str_addr));
		sprintf(str_x, " %-15s", str_addr);
	} else {
		sprintf(str_x, " %-15s", "default");
	}
	strcat(m_str, str_x);

	str_x[0] = '\0';
	if (m_dst_mask != 0) {
		inet_ntop(AF_INET, &m_dst_mask_in_addr, str_addr, sizeof(str_addr));
		sprintf(str_x, " netmask: %-15s", str_addr);
	}
	strcat(m_str, str_x);

	str_x[0] = '\0';
	if (m_gw != 0) {
		inet_ntop(AF_INET, &m_gw_in_addr, str_addr, sizeof(str_addr));
		sprintf(str_x, " gw:      %-15s", str_addr);
	}
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " dev: %-5s", m_if_name);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	if (m_src_addr != 0) {
		inet_ntop(AF_INET, &m_src_addr_in_addr, str_addr, sizeof(str_addr));
		sprintf(str_x, " src: %-15s", str_addr);
	} else {
		sprintf(str_x, "                     ");
	}
	strcat(m_str, str_x);
			
	str_x[0] = '\0';
	if (m_table_id != RT_TABLE_MAIN) {
		sprintf(str_x, " table :%-10u", m_table_id);
	} else {
		sprintf(str_x, " table :%-10s", "main");
	}		
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " scope %3d type %2d index %2d", m_scope, m_type, m_if_index);
	strcat(m_str, str_x);
	// add route metrics
	if (m_mtu) {
		sprintf(str_x, " mtu %d", m_mtu);
		strcat(m_str, str_x);
	}
	if (m_b_deleted) {
		sprintf(str_x, " ---> DELETED");
	}
	strcat(m_str, str_x);
}

void route_val::print_val()
{
	set_str();
	rt_val_logdbg("%s", to_str());
}

void route_val::set_mtu(uint32_t mtu)
{
	if (mtu > g_p_net_device_table_mgr->get_max_mtu()) {
		rt_val_logdbg("route mtu cannot be bigger then max mtu set on devices");
	} else {
		m_mtu = mtu;
	}
}
