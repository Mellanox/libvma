/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef RFS_UC_H
#define RFS_UC_H

#include "vma/dev/rfs.h"


/**
 * @class rfs_uc
 *
 * Object to manages the sink list of a UC flow
 * This object is used for maintaining the sink list and dispatching packets
 *
 */


class rfs_uc : public rfs
{
public:
	rfs_uc(flow_tuple *flow_spec_5t, ring_slave *p_ring,
	       rfs_rule_filter* rule_filter = NULL, uint32_t flow_tag_id = 0);

	virtual bool rx_dispatch_packet(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array);

protected:
	virtual void prepare_flow_spec();
};


#endif /* RFS_UC_H */
