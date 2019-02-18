/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef NETLINK_EVENT_H_
#define NETLINK_EVENT_H_

#include <netlink/msg.h>
#include "config.h"
#include "vma/event/event.h"
#include "vma/netlink/neigh_info.h"
#include "vma/netlink/route_info.h"
#include "vma/netlink/link_info.h"
#include <linux/rtnetlink.h>

class netlink_link;
class netlink_neigh;

class netlink_event: public event
{
public:
	netlink_event(struct nlmsghdr* hdr, void* notifier);
	virtual ~netlink_event() { }


	/* netlink route family message types:
	 RTM_DELLINK
	 RTM_GETLINK
	 RTM_SETLINK
	 RTM_NEWADDR
	 RTM_DELADDR
	 RTM_GETADDR
	 RTM_NEWROUTE
	 RTM_DELROUTE
	 RTM_GETROUTE
	 RTM_NEWNEIGH
	 RTM_DELNEIGH
	 RTM_GETNEIGH
	 RTM_NEWRULE
	 RTM_DELRULE
	 RTM_GETRULE
	 RTM_NEWQDISC
	 RTM_DELQDISC
	 RTM_GETQDISC
	 RTM_NEWTCLASS
	 RTM_DELTCLASS
	 RTM_GETTCLASS
	 RTM_NEWTFILTER
	 RTM_DELTFILTER
	 RTM_GETTFILTER
	 RTM_NEWACTION
	 RTM_DELACTION
	 RTM_GETACTION
	 RTM_NEWPREFIX
	 RTM_GETPREFIX
	 RTM_GETMULTICAS
	 RTM_GETANYCAST
	 RTM_NEWNEIGHTBL
	 RTM_GETNEIGHTBL
	 RTM_SETNEIGHTBL
	 RTM_NEWADDRLABEL
	 RTM_DELADDRLABEL
	 RTM_GETADDRLABEL
	 */
	uint16_t nl_type;

	uint32_t nl_pid;
	uint32_t nl_seq;

	virtual  const std::string to_str() const;


};

class neigh_nl_event: public netlink_event
{
public:
	neigh_nl_event(struct nlmsghdr* hdr, struct rtnl_neigh* neigh,
	                void* notifier);

	virtual ~neigh_nl_event();

	virtual  const std::string to_str() const;

	const netlink_neigh_info* get_neigh_info() const { return m_neigh_info; }

private:
	netlink_neigh_info* m_neigh_info;

};

class route_nl_event: public netlink_event
{
public:
	route_nl_event(struct nlmsghdr* hdr, struct rtnl_route* route,
	                void* notifier);

	virtual ~route_nl_event();

	virtual  const std::string to_str() const;

	netlink_route_info* get_route_info() const { return m_route_info; }

private:
	netlink_route_info* m_route_info;

};

class link_nl_event: public netlink_event
{
public:
	link_nl_event(struct nlmsghdr* hdr, struct rtnl_link* rt_link,
	                void* notifier);

	virtual ~link_nl_event();

	virtual  const std::string to_str() const;

	const netlink_link_info* get_link_info() const { return m_link_info; }

private:
	netlink_link_info* m_link_info;
};

#endif /* NETLINK_EVENT_H_ */
