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
