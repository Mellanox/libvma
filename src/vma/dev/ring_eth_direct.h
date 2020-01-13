/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef SRC_VMA_DEV_RING_ETH_DIRECT_H_
#define SRC_VMA_DEV_RING_ETH_DIRECT_H_

#include <tr1/unordered_map>
#include "dev/ring_simple.h"


typedef std::pair<void*, size_t> pair_void_size_t;
typedef std::pair<uint32_t, int> pair_mr_ref_t;
namespace std { namespace tr1 {
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
}}

typedef std::tr1::unordered_map<pair_void_size_t, pair_mr_ref_t> addr_len_mr_map_t;

class ring_eth_direct : public ring_eth
{
public:
	ring_eth_direct(int if_index,
		    vma_external_mem_attr *ext_ring_attr, ring *parent = NULL);
	virtual		~ring_eth_direct();
	virtual qp_mgr*	create_qp_mgr(const ib_ctx_handler* ib_ctx,
					      uint8_t port_num,
					      struct ibv_comp_channel* p_rx_comp_event_channel);
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
