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


#ifndef NETLINK_EVENT_H_
#define NETLINK_EVENT_H_

#include <netlink/msg.h>
#include "vma/event/event.h"
#include "vma/netlink/neigh_info.h"
#include "vma/netlink/route_info.h"
#include "vma/netlink/link_info.h"
#include <linux/rtnetlink.h>
#include <netlink/object-api.h>


class netlink_link;
class netlink_neigh;

typedef struct { NLHDR_COMMON } _nl_object;

class netlink_event: public event
{
public:
	netlink_event(struct nlmsghdr* hdr, void* notifier);
	netlink_event(struct nl_object* obj, void* notifier);
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

	uint16_t nl_flags;
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

	const netlink_route_info* get_route_info() const { return m_route_info; }

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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	const netlink_link_info* get_link_info() const { return m_link_info; }
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

private:
	netlink_link_info* m_link_info;


};

#endif /* NETLINK_EVENT_H_ */
