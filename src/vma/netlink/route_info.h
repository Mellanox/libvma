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
			                0), pref_src_addr_str(""),pref_src_addr(NULL), pref_src_addr_len(0), pref_src_prefixlen(0), iif_name(""), oif(0)
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

	// outgoing interface index of the route
	int oif;
};

#endif /* NETLINK_ROUTE_INFO_H_ */
