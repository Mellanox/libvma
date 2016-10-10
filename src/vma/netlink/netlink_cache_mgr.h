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



#ifndef NETLINK_CACHE_MGR_H
#define NETLINK_CACHE_MGR_H

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/neighbour.h>

#include "vma/event/netlink_event.h"
#include "utils/lock_wrapper.h"
#include "netlink_compatibility.h"
#include "neigh_info.h"

#define	subject_map_iter map<e_os_network_data_event_type, subject*>::iterator

// structure to pass arguments on internal netlink callbacks handling
typedef struct rcv_msg_arg
{
	netlink_cache_mgr* nl_cache_mgr;
	nl_socket_handle* socket_handle;
	map<e_os_network_data_event_type, subject*>* subjects_map;
	nlmsghdr* msghdr;
} rcv_msg_arg_t;

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
class netlink_cache_mgr
{
public:
	netlink_cache_mgr();
	virtual ~netlink_cache_mgr();

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
	bool register_event(e_os_network_data_event_type type, const observer* new_obs);

	/*
	 *  unregister an observer from the subject specified by netlink event type
	 */
	bool unregister(e_os_network_data_event_type type, const observer* obs);

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
	// user of netlink_cache_mgr should provide context to call this function periodically.
	// ** Currently, it refills neigh's cache info from current kernel's table
	// 	because when neigh state is changed from STALE to REACHABLE directly , kernel does not notifies netlink
	void neigh_timer_expired();
	
protected:
	struct nl_cache* m_cache_neigh;	
	lock_mutex_recursive m_cache_lock;	

private:
	nl_socket_handle* m_socket_handle;

	struct nl_cache_mngr* m_mngr;
	struct nl_cache* m_cache_link;
	struct nl_cache* m_cache_route;

	map<e_os_network_data_event_type, subject*> m_subjects_map;
	lock_mutex_recursive m_subj_map_lock;

	//This method should be called with m_cache_lock held!
	static void notify_observers(netlink_event *p_new_event, e_os_network_data_event_type type);

	void notify_neigh_cache_entries();
};

#endif /* NETLINK_CACHE_MGR_H */
