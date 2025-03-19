/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */



#ifndef NETLINK_COMPATIBILITY_H_
#define NETLINK_COMPATIBILITY_H_

#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <fcntl.h>
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
in_addr_t nl_object_get_compatible_gateway(struct rtnl_route* nl_route_obj);
int nl_object_get_compatible_oif(struct rtnl_route* nl_route_obj);
int nl_object_get_compatible_metric(struct rtnl_route* nl_route_obj, int attr);


#endif /* NETLINK_COMPATIBILITY_H_ */
