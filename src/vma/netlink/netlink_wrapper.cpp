/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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


#include <pthread.h>
#include <net/route.h>

#include "vlogger/vlogger.h"
#include "utils/bullseye.h"
#include "netlink_wrapper.h"
#include <netlink/types.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/utils.h>

#define MODULE_NAME 		"nl_wrapper:"

#define nl_logpanic		__log_panic
#define nl_logerr		__log_err
#define nl_logwarn		__log_warn
#define nl_loginfo		__log_info
#define nl_logdbg		__log_dbg
#define nl_logfunc		__log_func

netlink_wrapper* g_p_netlink_handler = NULL;

// structure to pass arguments on internal netlink callbacks handling
typedef struct rcv_msg_arg
{
	netlink_wrapper* netlink;
	nl_socket_handle* socket_handle;
	map<e_netlink_event_type, subject*>* subjects_map;
	nlmsghdr* msghdr;
} rcv_msg_arg_t;

static rcv_msg_arg_t  	g_nl_rcv_arg;

int nl_msg_rcv_cb(struct nl_msg *msg, void *arg) {
	nl_logfunc( "---> nl_msg_rcv_cb");
	NOT_IN_USE(arg);
	g_nl_rcv_arg.msghdr = nlmsg_hdr(msg);
	// NETLINK MESAGE DEBUG
	//nl_msg_dump(msg, stdout);
	nl_logfunc( "<--- nl_msg_rcv_cb");
	return 0;
}

/* This function is called from internal thread only as neigh_timer_expired()
 * so it is protected by m_cache_lock call
 */
void netlink_wrapper::notify_observers(netlink_event *p_new_event, e_netlink_event_type type)
{
	g_nl_rcv_arg.netlink->m_cache_lock.unlock();
	g_nl_rcv_arg.netlink->m_subj_map_lock.lock();

	subject_map_iter iter = g_nl_rcv_arg.subjects_map->find(type);
	if(iter != g_nl_rcv_arg.subjects_map->end())
		iter->second->notify_observers(p_new_event);

	g_nl_rcv_arg.netlink->m_subj_map_lock.unlock();
	/* coverity[missing_unlock] */
	g_nl_rcv_arg.netlink->m_cache_lock.lock();
}

extern void link_event_callback(nl_object* obj) {
		netlink_wrapper::link_cache_callback(obj);
}
extern void neigh_event_callback(nl_object* obj) {
	netlink_wrapper::neigh_cache_callback(obj);
}
extern void route_event_callback(nl_object* obj) {
	netlink_wrapper::route_cache_callback(obj);
}

void netlink_wrapper::neigh_cache_callback(nl_object* obj)
{
	nl_logdbg( "---> neigh_cache_callback");
	struct rtnl_neigh* neigh = (struct rtnl_neigh*)obj;
	neigh_nl_event new_event(g_nl_rcv_arg.msghdr, neigh, g_nl_rcv_arg.netlink);

	netlink_wrapper::notify_observers(&new_event, nlgrpNEIGH);

	g_nl_rcv_arg.msghdr = NULL;
	nl_logdbg( "<--- neigh_cache_callback");

}

void netlink_wrapper::link_cache_callback(nl_object* obj)
{
	nl_logfunc( "---> link_cache_callback");
	struct rtnl_link* link = (struct rtnl_link*) obj;
	link_nl_event new_event(g_nl_rcv_arg.msghdr, link, g_nl_rcv_arg.netlink);

	netlink_wrapper::notify_observers(&new_event, nlgrpLINK);

	g_nl_rcv_arg.msghdr = NULL;
	nl_logfunc( "<--- link_cache_callback");
}

void netlink_wrapper::route_cache_callback(nl_object* obj)
{
	nl_logfunc( "---> route_cache_callback");
	struct rtnl_route* route = (struct rtnl_route*) obj;
	if (route) {
		int table_id = rtnl_route_get_table(route);
		int family = rtnl_route_get_family(route);
		if ((table_id > (int)RT_TABLE_UNSPEC) && (table_id != RT_TABLE_LOCAL) && (family == AF_INET)) {
			route_nl_event new_event(g_nl_rcv_arg.msghdr, route, g_nl_rcv_arg.netlink);
			netlink_wrapper::notify_observers(&new_event, nlgrpROUTE);
		}
		else {
			nl_logdbg("Received event for not handled route entry: family=%d, table_id=%d", family, table_id);
		}	
	}
	else {
		nl_logdbg("Received invalid route event");
	}
	g_nl_rcv_arg.msghdr = NULL;
	nl_logfunc( "<--- route_cache_callback");
}


netlink_wrapper::netlink_wrapper() :
		m_socket_handle(NULL), m_mngr(NULL), m_cache_link(NULL), m_cache_neigh(
		                NULL), m_cache_route(NULL)
{
	nl_logdbg( "---> netlink_route_listener CTOR");
	g_nl_rcv_arg.subjects_map = &m_subjects_map;
	g_nl_rcv_arg.netlink = this;
	g_nl_rcv_arg.msghdr = NULL;
	nl_logdbg( "<--- netlink_route_listener CTOR");
}

netlink_wrapper::~netlink_wrapper()
{
	/* different handling under LIBNL1 versus LIBNL3 */
#ifdef HAVE_LIBNL3
	nl_logdbg( "---> netlink_route_listener DTOR (LIBNL3)");
	/* should not call nl_cache_free() for link, neigh, route as nl_cach_mngr_free() does the freeing */
	// nl_cache_free(m_cache_link);
	// nl_cache_free(m_cache_neigh);
	// nl_cache_free(m_cache_route);
	nl_cache_mngr_free(m_mngr);	
	nl_socket_handle_free(m_socket_handle); 
#else // HAVE_LINBL1
	nl_logdbg( "---> netlink_route_listener DTOR (LIBNL1)");
	/* should not call nl_socket_handle_free(m_socket_handle) as nl_cache_mngr_free() does the freeing */ 
	/* nl_socket_handle_free(m_socket_handle); */
	nl_cache_free(m_cache_link);
	nl_cache_free(m_cache_neigh);
	nl_cache_free(m_cache_route);
	nl_cache_mngr_free(m_mngr);
#endif // HAVE_LIBNL3

	subject_map_iter iter = m_subjects_map.begin();
	while (iter != m_subjects_map.end()) {
		delete iter->second;
		iter++;
	}
	nl_logdbg( "<--- netlink_route_listener DTOR");
}

int netlink_wrapper::open_channel()
{
	auto_unlocker lock(m_cache_lock);
	nl_logdbg("opening netlink channel");

	/*
	 // build to subscriptions groups mask for indicating what type of events the kernel will send on channel
	 unsigned subscriptions = ~RTMGRP_TC;
	 if (netlink_route_group_mask & nlgrpLINK) {
	 subscriptions |= (1 << (RTNLGRP_LINK - 1));
	 }
	 if (netlink_route_group_mask & nlgrpADDRESS) {
	 if (!m_preferred_family || m_preferred_family == AF_INET)
	 subscriptions |= (1 << (RTNLGRP_IPV4_IFADDR - 1));
	 if (!m_preferred_family || m_preferred_family == AF_INET6)
	 subscriptions |= (1 << (RTNLGRP_IPV6_IFADDR - 1));
	 }
	 if (netlink_route_group_mask & nlgrpROUTE) {
	 if (!m_preferred_family || m_preferred_family == AF_INET)
	 subscriptions |= (1 << (RTNLGRP_IPV4_ROUTE - 1));
	 if (!m_preferred_family || m_preferred_family == AF_INET6)
	 subscriptions |= (1 << (RTNLGRP_IPV4_ROUTE - 1));
	 }
	 if (netlink_route_group_mask & nlgrpPREFIX) {
	 if (!m_preferred_family || m_preferred_family == AF_INET6)
	 subscriptions |= (1 << (RTNLGRP_IPV6_PREFIX - 1));
	 }
	 if (netlink_route_group_mask & nlgrpNEIGH) {
	 subscriptions |= (1 << (RTNLGRP_NEIGH - 1));
	 }
	 */

	// Allocate a new netlink socket/handle
	m_socket_handle = nl_socket_handle_alloc();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_socket_handle == NULL) {
		nl_logerr("failed to allocate netlink handle");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// set internal structure to pass the handle with callbacks from netlink
	g_nl_rcv_arg.socket_handle = m_socket_handle;

	// if multiple handles being allocated then a unique netlink PID need to be provided
	// If port is 0, a unique port identifier will be generated automatically as a unique PID
	nl_socket_set_local_port(m_socket_handle, 0);


	//Disables checking of sequence numbers on the netlink handle.
	//This is required to allow messages to be processed which were not requested by a preceding request message, e.g. netlink events.
	nl_socket_handle_disable_seq_check(m_socket_handle);

	//joining group
	//nl_join_groups(m_handle, 0);

	// Allocate a new cache manager for RTNETLINK
	// NL_AUTO_PROVIDE = automatically provide the caches added to the manager.
	m_mngr = nl_cache_mngr_compatible_alloc(m_socket_handle, NETLINK_ROUTE, NL_AUTO_PROVIDE);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_mngr) {
		nl_logerr("Fail to allocate cache manager");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	nl_logdbg("netlink socket is open");

	if (nl_cache_mngr_compatible_add(m_mngr, "route/link", link_callback, NULL, &m_cache_link))
		return -1;
	if (nl_cache_mngr_compatible_add(m_mngr, "route/route", route_callback, NULL, &m_cache_route))
		return -1;
	if (nl_cache_mngr_compatible_add(m_mngr, "route/neigh", neigh_callback, NULL, &m_cache_neigh))
		return -1;

	// set custom callback for every message to update message
	nl_socket_modify_cb(m_socket_handle, NL_CB_MSG_IN, NL_CB_CUSTOM, nl_msg_rcv_cb ,NULL);

	// set the socket non-blocking
	BULLSEYE_EXCLUDE_BLOCK_START
	if (nl_socket_set_nonblocking(m_socket_handle)) {
		nl_logerr("Failed to set the socket non-blocking");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;

}

int netlink_wrapper::get_channel()
{
	auto_unlocker lock(m_cache_lock);
	if (m_socket_handle)
		return nl_socket_get_fd(m_socket_handle);
	else
		return -1;
}

int netlink_wrapper::handle_events()
{
	m_cache_lock.lock();

	nl_logfunc("--->handle_events");

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_socket_handle) {
		nl_logerr("Cannot handle events before opening the channel. please call first open_channel()");
		m_cache_lock.unlock();
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	int n = nl_cache_mngr_data_ready(m_mngr);

	//int n = nl_recvmsgs_default(m_handle);
	nl_logfunc("nl_recvmsgs=%d", n);
	if (n < 0)
		nl_logdbg("recvmsgs returned with error = %d", n);


	nl_logfunc("<---handle_events");

	m_cache_lock.unlock();

	return n;
}

bool netlink_wrapper::register_event(e_netlink_event_type type,
                const observer* new_obs)
{
	auto_unlocker lock(m_subj_map_lock);
	subject* sub;
	subject_map_iter iter = m_subjects_map.find(type);
	if (iter == m_subjects_map.end()) {
		sub = new subject();
		m_subjects_map[type] = sub;
	}
	else {
		sub = m_subjects_map[type];
	}

	return sub->register_observer(new_obs);
}

bool netlink_wrapper::unregister(e_netlink_event_type type,
                const observer* obs)
{
	auto_unlocker lock(m_subj_map_lock);
	if (obs == NULL)
		return false;

	subject_map_iter iter = m_subjects_map.find(type);
	if (iter != m_subjects_map.end()) {
		return m_subjects_map[type]->unregister_observer(obs);
	}

	return true;
}

int netlink_wrapper::get_neigh(const char* ipaddr, int ifindex, netlink_neigh_info* new_neigh_info)
{
	auto_unlocker lock(m_cache_lock);
	nl_logfunc("--->netlink_listener::get_neigh");
	nl_object* obj;
	rtnl_neigh* neigh;
	char addr_str[256];

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!new_neigh_info) {
		nl_logerr("Illegal argument. user pass NULL neigh_info to fill");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	obj = nl_cache_get_first(m_cache_neigh);
	while (obj) {
		nl_object_get(obj); //Acquire a reference on a cache object. cache won't use/free it until calling to nl_object_put(obj)
		neigh = (rtnl_neigh*) obj;
		nl_addr* addr = rtnl_neigh_get_dst(neigh);
		int index = rtnl_neigh_get_ifindex(neigh);
		if ((addr) && (index > 0)) {
			nl_addr2str(addr, addr_str, 255);
			if (!strcmp(addr_str, ipaddr) && (ifindex == index)) {
				new_neigh_info->fill(neigh);
				nl_object_put(obj);
				nl_logdbg("neigh - DST_IP:%s IF_INDEX:%d LLADDR:%s", addr_str, index, new_neigh_info->lladdr_str.c_str() );
				nl_logfunc("<---netlink_listener::get_neigh");
				return 1;
			}
		}
		nl_object_put(obj);
		obj = nl_cache_get_next(obj);
	}

	nl_logfunc("<---netlink_listener::get_neigh");
	return 0;
}

void netlink_wrapper::neigh_timer_expired() {
	m_cache_lock.lock();

	nl_logfunc("--->netlink_wrapper::neigh_timer_expired");
	nl_cache_refill(m_socket_handle, m_cache_neigh);
	notify_neigh_cache_entries();
	nl_logfunc("<---netlink_wrapper::neigh_timer_expired");

	m_cache_lock.unlock();
}

void netlink_wrapper::notify_neigh_cache_entries() {
	nl_logfunc("--->netlink_wrapper::notify_cache_entries");
	g_nl_rcv_arg.msghdr = NULL;
	nl_object* obj = nl_cache_get_first(m_cache_neigh);
	while (obj) {
		nl_object_get(obj);
		neigh_event_callback(obj);
		nl_object_put(obj);
		obj = nl_cache_get_next(obj);
	}
	nl_logfunc("<---netlink_wrapper::notify_cache_entries");

}




