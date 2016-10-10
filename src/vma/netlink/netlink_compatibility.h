/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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
#include <map>
#include "vma/infra/subject_observer.h"
#include "vma/proto/os_network_data_wrapper.h"

using namespace std;

extern "C" void link_event_callback(nl_object* obj);
extern "C" void neigh_event_callback(nl_object* obj);
extern "C" void route_event_callback(nl_object* obj);

class netlink_cache_mgr;

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
