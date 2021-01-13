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


