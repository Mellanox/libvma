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


#include "link_info.h"
#include "vlogger/vlogger.h"

#define MODULE_NAME "netlink_event"

#define ADDR_MAX_STR_LEN (128)


netlink_link_info::netlink_link_info(struct rtnl_link* link):
		/*arptype(0),*/ broadcast_str(""), addr_family(0), flags(0), ifindex(
                0), /*mode(0),*/ master_ifindex(0), mtu(
                0), name(""), operstate(0), txqlen(
                0)
{
	fill(link);
}

void netlink_link_info::fill(struct rtnl_link* link)
{
	if (link) {
		//arptype=rtnl_link_get_arptype(link);
		addr_family=rtnl_link_get_family(link);
		flags=rtnl_link_get_flags(link);
		ifindex=rtnl_link_get_ifindex(link);
		master_ifindex=rtnl_link_get_master(link);
		mtu=rtnl_link_get_mtu(link);
		txqlen=rtnl_link_get_txqlen(link);
		operstate=rtnl_link_get_operstate(link);
		//mode=rtnl_link_get_linkmode(link);

		nl_addr* addr;
		char addr_str[ADDR_MAX_STR_LEN + 1];

		const char* namestr=rtnl_link_get_name(link);
		if (namestr) {
			name = namestr;
		}

		addr = rtnl_link_get_broadcast(link);
		if (addr) {
			broadcast_str = nl_addr2str(addr, addr_str, ADDR_MAX_STR_LEN);
		}

	}
}

const std::string netlink_link_info::get_operstate2str() const {
	char operstate_str[256];
	return rtnl_link_operstate2str(operstate,operstate_str, 255);
}
