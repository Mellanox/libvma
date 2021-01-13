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


#ifndef NETLINK_LINK_INFO_H_
#define NETLINK_LINK_INFO_H_

#include <netlink/route/link.h>
#include <iostream>

class netlink_link_info
{
public:
	netlink_link_info(struct rtnl_link* link);
	virtual ~netlink_link_info()
	{
	}

	// fill all attributes using the provided netlink original link
	void fill(struct rtnl_link* link);


//	// Hardware type (eg. ARPHRD_ETHER or ARPHRD_VOID)
//	uint32_t arptype;

	// the link layer broadcast address string
	std::string broadcast_str;

	// Address family or AF_UNSPEC if not specified.
	int addr_family;

	/* return link flags:
	 * IFF_UP 			Link is up (administratively)
	 * IFF_RUNNING 		Link is up and carrier is OK (RFC2863 OPER_UP)
	 * IFF_LOWER_UP 	Link layer is operational
	 * IFF_DORMANT		Driver signals dormant
	 * IFF_BROADCAST	Link supports broadcasting
	 * IFF_MULTICAST	Link supports multicasting
	 * IFF_ALLMULTI		Link supports multicast routing
	 * IFF_DEBUG		Tell driver to do debugging (currently unused)
	 * IFF_LOOPBACK		Link loopback network
	 * IFF_POINTOPOINT	Point-to-point link
	 * IFF_NOARP		ARP is not supported
	 * IFF_PROMISC		Status of promiscious mode
	 * IFF_MASTER		Master of a load balancer (bonding)
	 * IFF_SLAVE		Slave to a master link
	 * IFF_PORTSEL		Driver supports setting media type (only used by ARM ethernet)
	 * IFF_AUTOMEDIA	Link selects port automatically (only used by ARM ethernet)
	 * IFF_ECHO			Echo sent packets (testing feature, CAN only)
	 * IFF_DYNAMIC		Unused (BSD compatibility)
	 * IFF_NOTRAILERS	Unused (BSD compatibility)
	 *
	 */
	uint32_t flags;

	// the interface index of the link
	int ifindex;

//	/* the link mode
//	 * IF_LINK_MODE_DEFAULT Default link mode
//	 * IF_LINK_MODE_DORMANT Limit upward transition to dormant
//	 */
//	uint8_t mode;

	// interface index of master link or 0 if not specified
	int master_ifindex;

	/* the maximum transmission unit
	 * specifies the maximum packet size a network device can transmit or receive
	 * 	 */
	uint32_t mtu;

	/* a unique,human readable description of the link.
	 * by default, links are named based on their type and then enumerated,
	 * e.g. eth0, eth1, ethn but they may be renamed at any time
	 *  */
	std::string name;

	/* extended information on the link status (from: RFC 2863 operational status linux/if.h)
	 * 		Unknown state 		IF_OPER_UNKNOWN
	 * 		Link not present 	IF_OPER_NOTPRESENT
	 * 		Link down			IF_OPER_DOWN
	 * 		L1 down				IF_OPER_LOWERLAYERDOWN
	 * 		Testing				IF_OPER_TESTING
	 * 		Dormant				IF_OPER_DORMANT
	 * 		Link up 			IF_OPER_UP
	 *
	 */
	uint8_t operstate;

	// transmission queue length
	uint32_t txqlen;

	const std::string get_operstate2str() const;

};

#endif /* NETLINK_LINK_INFO_H_ */
