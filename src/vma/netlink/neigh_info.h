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


#ifndef NETLINK_NEIGH_INFO_H
#define NETLINK_NEIGH_INFO_H

#include <iostream>
#include <linux/rtnetlink.h>
#include <netlink/route/neighbour.h>

class netlink_neigh_info
{
public:
	netlink_neigh_info() :
		dst_addr_str(""),
		dst_addr(NULL),
		dst_addr_len(0),
		flags(0),
		ifindex(0),
		lladdr_str(""),
		lladdr(NULL),
		lladdr_len(0),
		state(0),
		type(0) {	}

	netlink_neigh_info(struct rtnl_neigh* neigh);
	virtual ~netlink_neigh_info() {}

	// fill all attributes using the provided netlink original neigh
	void fill(struct rtnl_neigh* neigh);

	// neigh's destination address as string
	std::string dst_addr_str; // rtnl_neigh_get_dst()

	// neigh's destination address
	unsigned char* dst_addr; //

	// neigh's destination address length
	uint32_t dst_addr_len;


//	// neigh addr family
//	int neigh_addr_family; //rtnl_neigh_get_family();

	/* return neigh flags:
	 * 		NTF_USE
	 * 		NTF_PROXY
	 * 		NTF_ROUTER
	 */
	uint32_t flags;

	// interface index OR RTNL_LINK_NOT_FOUND if not set
	int ifindex; //rtnl_neigh_get_ifindex();

	// link layer addr as string
	std::string lladdr_str; // rtnl_neigh_get_lladdr()

	// link layer addr
	unsigned char* lladdr;

	// link layer addr length
	uint32_t lladdr_len;

	/* neigh state:
	a bitmask of the following states:

        NUD_INCOMPLETE   a currently resolving cache entry
        NUD_REACHABLE    a confirmed working cache entry
        NUD_STALE        an expired cache entry
        NUD_DELAY        an entry waiting for a timer
        NUD_PROBE        a cache entry that is currently reprobed
        NUD_FAILED       an invalid cache entry
        NUD_NOARP        a device with no destination cache
        NUD_PERMANENT    a static entry

        -1 if not set.
	 * */
	int state; // rtnl_neigh_get_state();

	/*
	 * neigh type
	 * ?? not documented properly.
	 * -1 if not set
	 * 	 */
	int type; // rtnl_neigh_get_type();

	std::string get_state2str() const {
		if (state == -1) {
			return "NOT SET";
		}
		else if (state < 0) {
			return "ILLEGAL STATE";
		}
		else {
			char state_str[256];
			return rtnl_neigh_state2str(state, state_str, 255);
		}
	}

};

#endif /* NETLINK_NEIGH_INFO_H */
