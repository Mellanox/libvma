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


#include "route_info.h"

#define ADDR_MAX_STR_LEN (128)


netlink_route_info::netlink_route_info(struct rtnl_route* route) :
		table(0), scope(0), tos(0), protocol(0), priority(0), family(0), dst_addr_str(
		                ""), dst_addr(NULL), dst_addr_len(0), dst_prefixlen(
		                0), src_addr_str(""), src_addr(NULL), src_addr_len(
		                0), src_prefixlen(0), type(0), flags(0), pref_src_addr_str(
		                ""), pref_src_addr(NULL), pref_src_addr_len(0), pref_src_prefixlen(
		                0), iif_name(""), oif(0)
{
	fill(route);
}
void netlink_route_info::fill(struct rtnl_route* route) {
	if (route) {
		nl_addr* addr;
		char addr_str[ADDR_MAX_STR_LEN + 1];

		table=rtnl_route_get_table(route);
		scope=rtnl_route_get_scope(route);
		tos=rtnl_route_get_tos(route);
		protocol=rtnl_route_get_protocol(route);
		priority=rtnl_route_get_prio(route);
		family=rtnl_route_get_family(route);
		type=rtnl_route_get_type(route);
		flags=rtnl_route_get_flags(route);
		const char* iifstr=rtnl_route_get_iif(route);
		if(iifstr) {
			iif_name=iifstr;
		}
		oif=rtnl_route_get_oif(route);
		addr=rtnl_route_get_dst(route);
		if (addr) {
			dst_addr_str = nl_addr2str(addr, addr_str, ADDR_MAX_STR_LEN);
			dst_addr = (unsigned char*)nl_addr_get_binary_addr(addr);
			dst_addr_len = nl_addr_get_len(addr);
			dst_prefixlen = nl_addr_get_prefixlen(addr);

		}
		addr=rtnl_route_get_src(route);
		if (addr) {
			src_addr_str = nl_addr2str(addr, addr_str, ADDR_MAX_STR_LEN);
			src_addr = (unsigned char*)nl_addr_get_binary_addr(addr);
			src_addr_len = nl_addr_get_len(addr);
			src_prefixlen = nl_addr_get_prefixlen(addr);
		}
		addr=rtnl_route_get_pref_src(route);
		if (addr) {
			pref_src_addr_str = nl_addr2str(addr, addr_str, ADDR_MAX_STR_LEN);
			pref_src_addr = (unsigned char*)nl_addr_get_binary_addr(addr);
			pref_src_addr_len = nl_addr_get_len(addr);
			pref_src_prefixlen = nl_addr_get_prefixlen(addr);
		}
	}

}


