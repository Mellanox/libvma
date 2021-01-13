/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "netlink_compatibility.h"
#include "vma/util/if.h"

#define MODULE_NAME 		"nl_wrapper:"
#define nl_logerr		__log_err
#define nl_logwarn		__log_warn
#define nl_logdbg		__log_dbg


extern void link_event_callback(nl_object* obj);
extern void neigh_event_callback(nl_object* obj);
extern void route_event_callback(nl_object* obj);

#ifdef HAVE_LIBNL3

nl_sock* nl_socket_handle_alloc() {
	return nl_socket_alloc();
}

void nl_socket_handle_free(struct nl_sock * sock) {
	nl_socket_free(sock);
}

void neigh_callback(nl_cache* , nl_object* obj, int, void*) {
	neigh_event_callback(obj);
}

void link_callback(nl_cache* , nl_object* obj, int, void*) {
	link_event_callback(obj);
}

void route_callback(nl_cache* , nl_object* obj, int, void*) {
	route_event_callback(obj);
}

void nl_socket_handle_disable_seq_check(nl_socket_handle* handle) {
	return nl_socket_disable_seq_check(handle);
}

nl_cache_mngr* nl_cache_mngr_compatible_alloc(nl_socket_handle* handle, int protocol, int flags) {
	nl_cache_mngr* cache_mngr;

	/* allocate temporary 10 nl_sockets for marking the first 10 bits of user_port_map[0] (@[libnl/lib/socket.c]) as workaround
	 * to avoid conflict between the cache manager's internal sync socket and other netlink sockets on same process
	 */
	struct nl_sock* tmp_socket_arr[10];
	for (int i=0; i<10; i++) {
		tmp_socket_arr[i] = nl_socket_handle_alloc();
	}

	int err = nl_cache_mngr_alloc(handle, protocol, flags, &cache_mngr);

	// free the temporary sockets after cache manager was allocated and bounded the sync socket
	for (int i=0; i<10; i++) {
		nl_socket_free(tmp_socket_arr[i]);
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (err) {
		nl_logerr("Fail to allocate cache manager, error=%s", nl_geterror(err));
		return NULL;
	}
	int nl_socket_fd = nl_socket_get_fd(handle);
	if (fcntl(nl_socket_fd, F_SETFD, FD_CLOEXEC) != 0) {
		nl_logwarn("Fail in fctl, error = %d", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return cache_mngr;
}

int nl_cache_mngr_compatible_add(struct nl_cache_mngr*	mngr, const char* name, change_func_t cb, void*	data, struct nl_cache** result){
	int err = nl_cache_mngr_add(mngr, name, cb, data, result);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (err) {
		errno = ELIBEXEC;
		nl_logerr("Fail to add to cache manager, error=%s", nl_geterror(err));
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return err;
}

in_addr_t nl_object_get_compatible_gateway(struct rtnl_route* nl_route_obj) {
	struct rtnl_nexthop *nh;
	nh = rtnl_route_nexthop_n(nl_route_obj, 0);
	if (nh) {
		struct nl_addr * addr;
		addr = rtnl_route_nh_get_gateway(nh);
		if (addr) {
			return *(in_addr_t *) nl_addr_get_binary_addr(addr);
		}
	}
	return INADDR_ANY;
}

int nl_object_get_compatible_oif(struct rtnl_route* nl_route_obj) {
	struct rtnl_nexthop *nh;
	nh = rtnl_route_nexthop_n(nl_route_obj, 0);
	if (nh) {
		return rtnl_route_nh_get_ifindex(nh);
	}
	return -1;
}

int nl_object_get_compatible_metric(struct rtnl_route* nl_route_obj, int attr) {
	uint32_t val;

	int rc = rtnl_route_get_metric(nl_route_obj, attr, &val);
	if (rc == 0) {
		return val;
	}
	nl_logdbg("Fail parsing route metric %d error=%d\n", attr, rc);
	return 0;
}


#else //HAVE_LIBNL1

nl_handle* nl_socket_handle_alloc() {
	return nl_handle_alloc();
}

void nl_socket_handle_free(struct nl_handle* handle) {
	nl_handle_destroy(handle);
}

void neigh_callback(nl_cache* , nl_object* obj, int) {
	neigh_event_callback(obj);
}

void link_callback(nl_cache* , nl_object* obj, int) {
	link_event_callback(obj);
}

void route_callback(nl_cache* , nl_object* obj, int) {
	route_event_callback(obj);
}

void nl_socket_handle_disable_seq_check(nl_socket_handle* handle) {
	return nl_disable_sequence_check(handle);
}

nl_cache_mngr* nl_cache_mngr_compatible_alloc(nl_socket_handle* handle, int protocol, int flags) {
	nl_cache_mngr* cache_mgr = nl_cache_mngr_alloc(handle, protocol, flags);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!cache_mgr) {
		nl_logerr("Fail to allocate cache manager");
	}
	
	int nl_socket_fd = nl_socket_get_fd(handle);
	if (fcntl(nl_socket_fd, F_SETFD, FD_CLOEXEC) != 0) {
		nl_logwarn("Fail in fctl, error = %d", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return cache_mgr;
}

int nl_cache_mngr_compatible_add(struct nl_cache_mngr*	mngr, const char* name, change_func_t cb, void*	, struct nl_cache** result){
	*result = nl_cache_mngr_add(mngr, name, cb);
	if (*result == NULL) {
		errno = ELIBEXEC;
		nl_logerr("Fail adding to cache manager, error=%d %s\n",
			nl_get_errno(), nl_geterror());
		return -1;
	}
	return 0;
}

in_addr_t nl_object_get_compatible_gateway(struct rtnl_route* nl_route_obj) {
	struct nl_addr * addr;
	addr = rtnl_route_get_gateway(nl_route_obj);
	if (addr) {
		return *(in_addr_t *) nl_addr_get_binary_addr(addr);
	}
	return INADDR_ANY;
}

int nl_object_get_compatible_oif(struct rtnl_route* nl_route_obj) {
	return rtnl_route_get_oif(nl_route_obj);
}

int nl_object_get_compatible_metric(struct rtnl_route* nl_route_obj, int attr) {
	uint32_t val = rtnl_route_get_metric(nl_route_obj, attr);
	if (val == UINT_MAX) {
		nl_logdbg("Fail parsing route metric %d error=%d\n", attr, val);
		return 0;
	}
	return val;
}
#endif
