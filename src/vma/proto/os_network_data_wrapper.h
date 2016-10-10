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



#ifndef OS_NETWORK_DATA_WRAPPER_H_
#define OS_NETWORK_DATA_WRAPPER_H_

#include "vma/infra/cache_subject_observer.h"
#include "vma/netlink/neigh_info.h"
#include "route_val.h"
#include "route_lookup_key.h"

enum e_os_network_data_event_type
{
	NEIGH = 0,
	LINK = 1,
	ROUTE = 2,
	/* TODO: not supported yet
	ADDRESS=3,
	PREFIX=4,
	*/	
};

class os_network_data_wrapper
{
public:
	os_network_data_wrapper(){};
	virtual ~os_network_data_wrapper(){};
	
	virtual bool register_event(e_os_network_data_event_type type, const observer* new_obs) = 0;

	virtual bool unregister(e_os_network_data_event_type type, const observer* obs) = 0;

	virtual int get_neigh(const char* ipaddr, int ifindex, netlink_neigh_info* new_neigh_info) = 0;

	virtual bool route_resolve(route_lookup_key key, route_val *found_route_val = NULL, long timeout_usec = INFINITE_TIMEOUT) = 0;
	
};

extern os_network_data_wrapper* g_p_os_wrapper;

#endif /* OS_NETWORK_DATA_WRAPPER_H_ */
