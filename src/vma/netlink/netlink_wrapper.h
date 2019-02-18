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



#ifndef NETLINKROUTELISTENER_H_
#define NETLINKROUTELISTENER_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/neighbour.h>
#include "utils/lock_wrapper.h"
#include "neigh_info.h"
#include "vma/event/netlink_event.h"
#include "netlink_compatibility.h"

#define	subject_map_iter map<e_netlink_event_type, subject*>::iterator

/*
 * the class provide simple API for registering observers to NETLINK ROUTE_FAMILY events from kernel.
 * ROUTE_FAMILY: NEIGHBOURS, LINKS (interfaces), ROUTE TABLE, ADDRESSES
 * the user can register/unregister to different type of events with his own implemented observer.
 * netlink_listener doesn't manage an internal context for handling the events,
 * it provides the user with a method to handle the events on his context.
 *
 * the class uses LIBNL (netlink library) as an API to use netlink core functions
 * LIBNL documentation: http://www.infradead.org/~tgr/libnl/
 *
 * TODO:
 * 		-thread-safe
 * 		-currently supports only processing of NEIGH and LINK netlink kernel multicast groups
 */
class netlink_wrapper
{
public:
	netlink_wrapper();
	virtual ~netlink_wrapper();

	static void neigh_cache_callback(nl_object* obj);
	static void link_cache_callback(nl_object* obj);
	static void route_cache_callback(nl_object* obj);

	/* return fd for the specific netlink instace's channel to kernel
	 * the channel is a NON_BLOCKING socket opened as socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
	 * return <0 if channel is not open or failed to open.
	 */
	int get_channel();

	/*
	 * register an observer to a subject specified by type of netlink events.
	 * the registered observer will be notified for every netlink event related to the provided type
	 * events will be notified only from hadnle_events(). there is no internal context to handles the events,
	 * user need to provide a context by calling  hadnle_events().
	 */
	bool register_event(e_netlink_event_type type, const observer* new_obs);

	/*
	 *  unregister an observer from the subject specified by netlink event type
	 */
	bool unregister(e_netlink_event_type type, const observer* obs);

	/*
	 * Receive messages, parse, build relevant netlink_events and notify the registered observers.
	 * return the number of events or negative number on error
	 * **must first insure that opne_channel was called
	 */
	int handle_events();

	/* open the netlink channel:
	 1. Allocate a new netlink handle
	 2. [TODO: for querying]: allocate cache
	 3. join netlink multicast groups
	 4. Connect to link netlink socket on kernel side
	 5. set netlink callback
	 6. set the socket non-blocking
	 ** the channel must be opned before calling handle_events()
	 */
	int open_channel();

	// search for the first matching neigh using (ipaddr and ifindex) on the neigh cache
	// if matching neigh was found, then it fills the provided new_neigh_info* and return 1
	// else if no matching neigh then return 0
	// on error return -1
	// ** neigh cache is keep being updated for every neigh netlink event
	int get_neigh(const char* ipaddr, int ifindex, netlink_neigh_info* new_neigh_info);

	// periodic maintenance method for keeping caches updated with kernel.
	// user of netlink wrapper should provide context to call this function periodically.
	// ** Currently, it refills neigh's cache info from current kernel's table
	// 	because when neigh state is changed from STALE to REACHABLE directly , kernel does not notifies netlink
	void neigh_timer_expired();

private:
	nl_socket_handle* m_socket_handle;

	struct nl_cache_mngr* m_mngr;
	struct nl_cache* m_cache_link;
	struct nl_cache* m_cache_neigh;
	struct nl_cache* m_cache_route;

	map<e_netlink_event_type, subject*> m_subjects_map;
	lock_mutex_recursive m_cache_lock;
	lock_mutex_recursive m_subj_map_lock;

	//This method should be called with m_cache_lock held!
	static void notify_observers(netlink_event *p_new_event, e_netlink_event_type type);

	void notify_neigh_cache_entries();
};

extern netlink_wrapper* g_p_netlink_handler;

#endif /* NETLINKROUTELISTENER_H_ */
