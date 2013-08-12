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



#ifndef NETLINKROUTELISTENER_H_
#define NETLINKROUTELISTENER_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/cache-api.h>
#include <netlink/route/neighbour.h>
#include "neigh_info.h"
#include "vma/infra/subject_observer.h"
#include "vma/util/lock_wrapper.h"
#include "vma/event/netlink_event.h"
#include <map>
using namespace std;

enum e_netlink_event_type
{
	nlgrpNEIGH = 0,
	nlgrpLINK = 1,
	nlgrpROUTE = 2,
	/* TODO: not supported yet
	nlgrpADDRESS=3,
	nlgrpPREFIX=4,
	*/
};

#define	subject_map_iter map<e_netlink_event_type, subject*>::iterator

class netlink_wrapper;


// structure to pass arguments on internal netlink callbacks handling
typedef struct rcv_msg_arg
{
	netlink_wrapper* netlink;
	struct nl_handle* handle;
	map<e_netlink_event_type, subject*>* subjects_map;
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
class netlink_wrapper
{
public:
	netlink_wrapper();
	virtual ~netlink_wrapper();

	static void neigh_cache_callback(nl_cache* , nl_object* obj, int);
	static void link_cache_callback(nl_cache* , nl_object* obj, int);
	static void route_cache_callback(nl_cache* , nl_object* obj, int);

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

	// search for the first matching neigh with ipaddr on the nigh cache
	// if matching neigh was found, then it fills the provided new_neigh_info* and return 1
	// else if no matching neigh then return 0
	// on error return -1
	// ** neigh cache is keep being updated for every neigh netlink event
	int get_neigh(const char* ipaddr, netlink_neigh_info* new_neigh_info);

	// periodic maintenance method for keeping caches updated with kernel.
	// user of netlink wrapper should provide context to call this function periodically.
	// ** Currently, it refills neigh's cache info from current kernel's table
	// 	because when neigh state is changed from STALE to REACHABLE directly , kernel does not notifies netlink
	void neigh_timer_expired();

private:
	struct nl_handle* m_handle;

	struct nl_cache_mngr* m_mngr;
	struct nl_cache* m_cache_link;
	struct nl_cache* m_cache_neigh;
	struct nl_cache* m_cache_route;

	map<e_netlink_event_type, subject*> m_subjects_map;
	lock_mutex_recursive m_cache_lock;
	lock_mutex_recursive m_subj_map_lock;

	//This method should be called with m_cache_lock held!
	static void notify_observers(netlink_event *p_new_event, e_netlink_event_type type);

	void notify_cache_entries(struct nl_cache* cache);

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	static const char* get_event_type_name(e_netlink_event_type type)
	{
		static const char *event_type_string[] =
		{ "NEIGH", "LINK", "ROUTE", "ADDRESS", "PREFIX", };

		return event_type_string[type];

	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
};

extern netlink_wrapper* g_p_netlink_handler;

#endif /* NETLINKROUTELISTENER_H_ */
