/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "route_info.h"
#include "config.h"
#include "vma/util/if.h"
#include "vma/util/libvma.h"
#include "vlogger/vlogger.h"
#include "netlink_compatibility.h"

#define MODULE_NAME 		"route_info:"
#define ADDR_MAX_STR_LEN (128)

netlink_route_info::netlink_route_info(struct rtnl_route* nl_route_obj) : m_route_val(NULL)
{
	fill(nl_route_obj);
}

netlink_route_info::~netlink_route_info()
{
	if (m_route_val) {
		delete m_route_val;
	}
}
void netlink_route_info::fill(struct rtnl_route* nl_route_obj)
{
	if (!nl_route_obj) {
		return;
	}
	
	m_route_val = new route_val();
	if (!m_route_val) {
		__log_warn("Failed to allocate memory for new route object");
		return;
	}
	
	int table = rtnl_route_get_table(nl_route_obj);
	if (table > 0) {
		m_route_val->set_table_id(table);
	}
	
	int scope = rtnl_route_get_scope(nl_route_obj);
	if (scope > 0) {
		m_route_val->set_scope(scope);
	}
	int mtu = nl_object_get_compatible_metric(nl_route_obj, RTAX_MTU);
	if (mtu > 0) {
		m_route_val->set_mtu(mtu);
	}
	int protocol = rtnl_route_get_protocol(nl_route_obj);
	if (protocol > 0) {
		m_route_val->set_protocol(protocol);
	}
	
	int type = rtnl_route_get_type(nl_route_obj);
	if (type > 0) {
		m_route_val->set_type(type);
	}
	
	struct nl_addr* addr = rtnl_route_get_dst(nl_route_obj);
	if (addr) {
		unsigned int dst_prefixlen = nl_addr_get_prefixlen(addr);
		m_route_val->set_dst_mask(htonl(VMA_NETMASK(dst_prefixlen)));
		m_route_val->set_dst_pref_len(dst_prefixlen);
		m_route_val->set_dst_addr(*(in_addr_t *) nl_addr_get_binary_addr(addr));
	}
	
	addr = rtnl_route_get_pref_src(nl_route_obj);
	if (addr) {
		m_route_val->set_src_addr(*(in_addr_t *) nl_addr_get_binary_addr(addr));
	}
	
	int oif = nl_object_get_compatible_oif(nl_route_obj);
	if (oif > 0) {
		m_route_val->set_if_index(oif);
		char if_name[IFNAMSIZ];
		if_indextoname(oif, if_name);
		m_route_val->set_if_name(if_name);
	}
	
	in_addr_t gateway = nl_object_get_compatible_gateway(nl_route_obj);
	if (gateway != INADDR_ANY) {
		m_route_val->set_gw(gateway);
	}
}


