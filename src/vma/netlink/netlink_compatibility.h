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



#ifndef NETLINK_COMPATIBILITY_H_
#define NETLINK_COMPATIBILITY_H_

#include <asm/types.h>
#include <sys/socket.h>
#include "config.h"
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/object-api.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include "vma/infra/subject_observer.h"
#include <map>
using namespace std;

extern "C" void link_event_callback(nl_object* obj);
extern "C" void neigh_event_callback(nl_object* obj);
extern "C" void route_event_callback(nl_object* obj);

class netlink_wrapper;
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

#ifdef HAVE_LIBNL3

typedef struct nl_sock nl_socket_handle;
#define rtnl_compatible_route_get_priority rtnl_route_get_priority

nl_sock* nl_socket_handle_alloc();
void nl_socket_handle_free(struct nl_sock * sock);
void neigh_callback(nl_cache* , nl_object* obj, int, void*);
void link_callback(nl_cache* , nl_object* obj, int, void*);
void route_callback(nl_cache* , nl_object* obj, int, void*);

#else //HAVE_LIBNL1

#define rtnl_compatible_route_get_priority rtnl_route_get_prio
typedef struct { NLHDR_COMMON } _nl_object;
typedef struct nl_handle nl_socket_handle;

nl_handle* nl_socket_handle_alloc();
void nl_socket_handle_free(struct nl_handle* handle);
void neigh_callback(nl_cache* , nl_object* obj, int);
void link_callback(nl_cache* , nl_object* obj, int);
void route_callback(nl_cache* , nl_object* obj, int);

#endif

void nl_socket_handle_disable_seq_check(nl_socket_handle* handle);
nl_cache_mngr* nl_cache_mngr_compatible_alloc(nl_socket_handle* handle, int protocol, int flags);
int nl_cache_mngr_compatible_add(struct nl_cache_mngr*	mngr, const char* name, change_func_t cb, void*	data, struct nl_cache** result);
int nl_object_get_compatible_msgtype(const struct nl_object* obj);
const char*	get_rtnl_route_iif_name(struct rtnl_route* route);

#endif /* NETLINK_COMPATIBILITY_H_ */
