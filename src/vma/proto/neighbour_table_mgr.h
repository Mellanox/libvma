/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef NEIGHBOUR_TABLE_MGR_H
#define NEIGHBOUR_TABLE_MGR_H

#include "vma/proto/neighbour.h"
#include "vma/infra/cache_subject_observer.h"

class neigh_table_mgr : public cache_table_mgr<neigh_key, class neigh_val*>, public observer
{
public:
				neigh_table_mgr();
				~neigh_table_mgr();
	virtual void 		notify_cb(event * event);
	rdma_event_channel*	m_neigh_cma_event_channel;
	bool			register_observer(neigh_key,
					const cache_observer *,
					cache_entry_subject<neigh_key, class neigh_val*> **);

private:
	/* This function will retrieve neigh transport type by the following actions:
	 * 1. go to route manager table and get route entry according to the peer ip
	 * 2. get netdev from route entry
	 * 3. get transport type from netdev
	 */
	neigh_entry*		create_new_entry(neigh_key neigh_key, const observer* dst);
};

extern neigh_table_mgr *g_p_neigh_table_mgr;


#endif /* NEIGHBOUR_TABLE_MGR_H */
