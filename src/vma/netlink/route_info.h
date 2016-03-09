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


#ifndef NETLINK_ROUTE_INFO_H_
#define NETLINK_ROUTE_INFO_H_

#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include <iostream>

class netlink_route_info
{
public:
	netlink_route_info() :
			table(0), scope(0), tos(0), protocol(0), priority(0), family(
			                0), dst_addr_str(""), dst_addr(NULL), dst_addr_len(0), dst_prefixlen(0), src_addr_str(""), src_addr(NULL), src_addr_len(0), src_prefixlen(0), type(0), flags(
			                0), pref_src_addr_str(""),pref_src_addr(NULL), pref_src_addr_len(0), pref_src_prefixlen(0), iif_name("")
	{
	}

	netlink_route_info(struct rtnl_route* route);
	virtual ~netlink_route_info()
	{
	}

	// fill all attributes using the provided netlink original route
	void fill(struct rtnl_route* route);

	// table id of route or -1 if not set
	uint32_t table;

	// scope of a route pr -1 if not set
	uint8_t scope;

	// TOS (type of service) of the route or -1 if not set
	uint8_t tos;

	// protocol of a route or -1 if not set
	uint8_t protocol;

	// priority of a route or -1 if not set
	uint32_t priority;

	// address family of the route or AF_UNSPEC if not set
	uint8_t family;

	// destination address as string
	std::string dst_addr_str;
	// destination address
	unsigned char* dst_addr;
	// length of destination address
	uint32_t dst_addr_len;
	// prefix length of destination address
	uint32_t dst_prefixlen;


	// source address as string
	std::string src_addr_str;
	// source address
	unsigned char* src_addr;
	// length of source address
	uint32_t src_addr_len;
	// prefix length of source address
	uint32_t src_prefixlen;

	/*
	 * type of route:
	 RTN_UNSPEC,
	 RTN_UNICAST,		 Gateway or direct route
	 RTN_LOCAL,		 Accept locally
	 RTN_BROADCAST,		 Accept locally as broadcast,send as broadcast
	 RTN_ANYCAST,		 Accept locally as broadcast, but send as unicast
	 RTN_MULTICAST,		 Multicast route
	 RTN_BLACKHOLE,		 Drop
	 RTN_UNREACHABLE,	 Destination is unreachable
	 RTN_PROHIBIT,		 Administratively prohibited
	 RTN_THROW,		 Not in this table
	 RTN_NAT,		 Translate this address
	 RTN_XRESOLVE,		 Use external resolver
	 */
	uint8_t type;

	// flags of route
	uint32_t flags;

	// preferred source address as string
	std::string pref_src_addr_str;
	// preferred source address
	unsigned char* pref_src_addr;
	// length of preferred source address
	uint32_t pref_src_addr_len;
	// prefix length of preferred source address
	uint32_t pref_src_prefixlen;


	// incoming interface name of the route
	std::string iif_name;

};

#endif /* NETLINK_ROUTE_INFO_H_ */
