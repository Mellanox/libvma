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


#ifndef NEIGHBOUR_TABLE_MGR_H
#define NEIGHBOUR_TABLE_MGR_H

#include "vma/proto/neighbour.h"
#include "vma/infra/cache_subject_observer.h"

class neigh_table_mgr : public cache_table_mgr<neigh_key, class neigh_val*>, public observer
{
public:
				neigh_table_mgr();
				~neigh_table_mgr(){ stop_garbage_collector();};
	virtual void 		notify_cb(event * event);
	rdma_event_channel*	m_neigh_cma_event_channel;

private:
	/* This function will retrieve neigh transport type by the following actions:
	 * 1. go to route manager table and get route entry according to the peer ip
	 * 2. get netdev from route entry
	 * 3. get transport type from netdev
	 */
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	transport_type_t 	get_neigh_transport_type(ip_address peer_ip) { NOT_IN_USE(peer_ip); return VMA_TRANSPORT_ETH; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	neigh_entry*		create_new_entry(neigh_key neigh_key, const observer* dst);

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	void 			monitor_neighs() {};
	void 			keep_active() {};
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	void 			compare_L2_address();
};

extern neigh_table_mgr *g_p_neigh_table_mgr;


#endif /* NEIGHBOUR_TABLE_MGR_H */
