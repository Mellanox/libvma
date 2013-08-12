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


#include <netinet/in.h>
#include "neigh_info.h"

#define ADDR_MAX_STR_LEN (128)

netlink_neigh_info::netlink_neigh_info(struct rtnl_neigh* neigh) :
		dst_addr_str(""), dst_addr(NULL), dst_addr_len(0), flags(0), ifindex(
		                0), lladdr_str(""), lladdr(NULL), lladdr_len(0), state(
		                0), type(0)
{
	fill(neigh);
}

void netlink_neigh_info::fill(struct rtnl_neigh* neigh)
{
	if (!neigh) 
		return;

	nl_addr* addr;
	char addr_str[ADDR_MAX_STR_LEN + 1];

	addr = rtnl_neigh_get_dst(neigh);
	if (addr) {
		dst_addr_str = nl_addr2str(addr, addr_str, ADDR_MAX_STR_LEN);
		dst_addr = (unsigned char*)nl_addr_get_binary_addr(addr);
		dst_addr_len = nl_addr_get_len(addr);
	}

	addr = rtnl_neigh_get_lladdr(neigh);
	if (addr) {
		lladdr_str = nl_addr2str(addr, addr_str, ADDR_MAX_STR_LEN);
		lladdr = (unsigned char*)nl_addr_get_binary_addr(addr);
		lladdr_len = nl_addr_get_len(addr);
	}
	//addr_family = rtnl_neigh_get_family(neigh);
	flags = rtnl_neigh_get_flags(neigh);
	ifindex = rtnl_neigh_get_ifindex(neigh);
	state = rtnl_neigh_get_state(neigh);
	type = rtnl_neigh_get_type(neigh);
}


