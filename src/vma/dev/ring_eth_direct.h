/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SRC_VMA_DEV_RING_ETH_DIRECT_H_
#define SRC_VMA_DEV_RING_ETH_DIRECT_H_

#include <unordered_map>
#include "dev/ring_simple.h"


typedef std::pair<void*, size_t> pair_void_size_t;
typedef std::pair<uint32_t, int> pair_mr_ref_t;
namespace std {
template<>
class hash<pair_void_size_t>
{
public:
	size_t operator()(const pair_void_size_t &key) const
	{
		hash<size_t>_hash;
		return _hash((uint64_t)key.first ^ key.second);
	}
};
}

typedef std::unordered_map<pair_void_size_t, pair_mr_ref_t> addr_len_mr_map_t;

class ring_eth_direct : public ring_eth
{
public:
	ring_eth_direct(int if_index,
		    vma_external_mem_attr *ext_ring_attr, ring *parent = NULL);
	virtual		~ring_eth_direct();
	virtual qp_mgr*	create_qp_mgr(struct qp_mgr_desc *desc);
	// memory handler
	virtual int	reg_mr(void *addr, size_t length, uint32_t &lkey);
	virtual int	dereg_mr(void *addr, size_t length);
	// dummy functions to block memory usage and internal thread
	virtual void	init_tx_buffers(uint32_t count);
	virtual mem_buf_desc_t* mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);
	virtual int	drain_and_proccess(cq_type_t cq_type);
	virtual int	poll_and_process_element_rx(uint64_t* p_cq_poll_sn,
					void* pv_fd_ready_array);
private:
	vma_external_mem_attr	m_ring_attr;
	addr_len_mr_map_t	m_mr_map;
};


#endif /* SRC_VMA_DEV_RING_ETH_DIRECT_H_ */
