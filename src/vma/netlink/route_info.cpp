/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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


#include "route_info.h"
#include "config.h"
#include "vma/util/if.h"
#include "netlink_compatibility.h"
#define ADDR_MAX_STR_LEN (128)


netlink_route_info::netlink_route_info(struct rtnl_route* route) :
		table(0), scope(0), tos(0), protocol(0), priority(0), family(0), dst_addr_str(
		                ""), dst_addr(NULL), dst_addr_len(0), dst_prefixlen(
		                0), src_addr_str(""), src_addr(NULL), src_addr_len(
		                0), src_prefixlen(0), type(0), flags(0), pref_src_addr_str(
		                ""), pref_src_addr(NULL), pref_src_addr_len(0), pref_src_prefixlen(
		                0), iif_name("")
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
		family=rtnl_route_get_family(route);
		type=rtnl_route_get_type(route);
		flags=rtnl_route_get_flags(route);
		const char* iifstr=get_rtnl_route_iif_name(route);
		if (iifstr) {
			iif_name=iifstr;
		}
		priority=rtnl_compatible_route_get_priority(route);
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


