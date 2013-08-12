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


#include "netlink_event.h"
#include "vlogger/vlogger.h"
#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include "stdio.h"

#define TOSTR_MAX_SIZE 4096

netlink_event::netlink_event(struct nlmsghdr* hdr, void* notifier) :
		event(notifier), nl_type(0), nl_flags(0), nl_pid(0), nl_seq(0)
{
	if (hdr) {
		nl_type = hdr->nlmsg_type;
		nl_flags = hdr->nlmsg_flags;
		nl_pid = hdr->nlmsg_pid;
		nl_seq = hdr->nlmsg_seq;
	}

}

netlink_event::netlink_event(struct nl_object* obj, void* notifier) :
		event(notifier), nl_type(0), nl_flags(0), nl_pid(0), nl_seq(0)
{
	if (obj) {
		_nl_object* _obj = (_nl_object*)obj;

		nl_type = _obj->ce_msgtype;
		nl_flags = _obj->ce_flags;
	}

}


#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

const std::string netlink_event::to_str() const
{
	char outstr[TOSTR_MAX_SIZE];
	sprintf(outstr, "%s. NETLINK: TYPE=%u, FLAGS=%u PID=%u SEQ=%u",
	                event::to_str().c_str(),  nl_type, nl_flags, nl_pid,
	                nl_seq);
	return std::string(outstr);
}

const std::string neigh_nl_event::to_str() const
{
	char outstr[TOSTR_MAX_SIZE];
	sprintf(outstr,
	                "%s. NEIGH: DST_ADDR=%s LINK_ADDR=%s FLAGS=%u IFINDEX=%d STATE=%d TYPE=%d",
	                netlink_event::to_str().c_str(),
	                m_neigh_info->dst_addr_str.c_str(),
	                m_neigh_info->lladdr_str.c_str(), m_neigh_info->flags,
	                m_neigh_info->ifindex, m_neigh_info->state,
	                m_neigh_info->type);
	return std::string(outstr);

}

const std::string route_nl_event::to_str() const
{
	char outstr[TOSTR_MAX_SIZE];
	sprintf(outstr,
	                "%s. ROUTE: TABBLE=%u SCOPE=%u TOS=%u PROTOCOL=%u PRIORITY=%u FAMILY=%u DST_ADDR=%s DST_PREFIX=%u SRC_ADDR=%s SRC_PREFIX=%u TYPE=%u FALGS=%u PREF_SRC=%s IFF_NAME=%s OIF=%d",
	                netlink_event::to_str().c_str(), m_route_info->table,
	                m_route_info->scope, m_route_info->tos,
	                m_route_info->protocol, m_route_info->priority,
	                m_route_info->family, m_route_info->dst_addr_str.c_str(), m_route_info->dst_prefixlen,
	                m_route_info->src_addr_str.c_str(), m_route_info->src_prefixlen, m_route_info->type,
	                m_route_info->flags, m_route_info->pref_src_addr_str.c_str(),
	                m_route_info->iif_name.c_str(), m_route_info->oif);
	return std::string(outstr);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

neigh_nl_event::neigh_nl_event(struct nlmsghdr* hdr, struct rtnl_neigh* neigh,
                void* notifier) :
		netlink_event(hdr, notifier), m_neigh_info(NULL)
{
	m_neigh_info = new netlink_neigh_info(neigh);
	if ((!hdr) && (neigh)) {
		nl_type = rtnl_neigh_get_type(neigh);
		nl_flags = rtnl_neigh_get_flags(neigh);
	}
}

neigh_nl_event::~neigh_nl_event() {
	if (m_neigh_info)
		delete m_neigh_info;
}

route_nl_event::route_nl_event(struct nlmsghdr* hdr, struct rtnl_route* route,
                void* notifier) :
		netlink_event(hdr, notifier), m_route_info(NULL)
{
	m_route_info = new netlink_route_info(route);
}

route_nl_event::~route_nl_event()
{
	if (m_route_info)
		delete m_route_info;
}
link_nl_event::link_nl_event(struct nlmsghdr* hdr, struct rtnl_link* rt_link,
                void* notifier) :
		netlink_event(hdr, notifier)
{
	m_link_info = new netlink_link_info(rt_link);
}

link_nl_event::~link_nl_event() {
	if (m_link_info)
		delete m_link_info;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

const std::string link_nl_event::to_str() const
{
	char outstr[TOSTR_MAX_SIZE];
	sprintf(outstr,
	                //"%s. LINK: ARPTYPE=%u BROADCAST=%s ADDR_FAMILY=%d FLAGS=%u IFINDEX=%d MODE=%u MASTER_IFINDEX=%d MTU=%u NAME=%s OPERSTATE=%u TXQLEN=%u",
	                "%s. LINK: BROADCAST=%s ADDR_FAMILY=%d FLAGS=%u IFINDEX=%d MASTER_IFINDEX=%d MTU=%u NAME=%s OPERSTATE=%s TXQLEN=%u",
	                netlink_event::to_str().c_str(),/* m_link_info->arptype,*/
	                m_link_info->broadcast_str.c_str(), m_link_info->addr_family,
	                m_link_info->flags, m_link_info->ifindex,
	                /*m_link_info->mode,*/ m_link_info->master_ifindex,
	                m_link_info->mtu, m_link_info->name.c_str(),
	                m_link_info->get_operstate2str().c_str(), m_link_info->txqlen);

	return std::string(outstr);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

