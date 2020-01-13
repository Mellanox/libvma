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

#include "ring_eth_direct.h"
#include "qp_mgr_eth_direct.h"


#undef  MODULE_NAME
#define MODULE_NAME		"ring_direct"
#undef  MODULE_HDR
#define MODULE_HDR		MODULE_NAME "%d:%s() "


ring_eth_direct::ring_eth_direct(int if_index,
				vma_external_mem_attr *ext_ring_attr, ring *parent):
					ring_eth(if_index,
						parent, RING_ETH_DIRECT, false)
{
	m_ring_attr.comp_mask = ext_ring_attr->comp_mask;

	/* Complete resources initialization */
	ring_simple::create_resources();
}

qp_mgr* ring_eth_direct::create_qp_mgr(const ib_ctx_handler* ib_ctx,
					uint8_t port_num,
					struct ibv_comp_channel* p_rx_comp_event_channel)
{
#if defined(DEFINED_DIRECT_VERBS)
	return new qp_mgr_eth_direct(this, ib_ctx, port_num, p_rx_comp_event_channel,
				     get_tx_num_wr(), m_partition);
#endif
	NOT_IN_USE(ib_ctx);
	NOT_IN_USE(port_num);
	NOT_IN_USE(p_rx_comp_event_channel);
	return NULL;
}

void ring_eth_direct::init_tx_buffers(uint32_t count)
{
	NOT_IN_USE(count);
}

mem_buf_desc_t* ring_eth_direct::mem_buf_tx_get(ring_user_id_t id, bool b_block,
						int n_num_mem_bufs)
{
	NOT_IN_USE(id);
	NOT_IN_USE(b_block);
	NOT_IN_USE(n_num_mem_bufs);
	return NULL;
}

int ring_eth_direct::drain_and_proccess(cq_type_t cq_type)
{
	NOT_IN_USE(cq_type);
	return 0;
}

int ring_eth_direct::poll_and_process_element_rx(uint64_t* p_cq_poll_sn,
						 void* pv_fd_ready_array)
{
	NOT_IN_USE(p_cq_poll_sn);
	NOT_IN_USE(pv_fd_ready_array);
	return 0;
}

int ring_eth_direct::reg_mr(void *addr, size_t length, uint32_t &lkey)
{
	ring_logdbg("reg_mr()");
	if (unlikely(addr == NULL) || length == 0) {
		ring_logdbg("address is %p length is %zd", addr, length);
		errno = EINVAL;
		return -1;
	}
	auto_unlocker lock(m_lock_ring_tx);

	addr_len_mr_map_t::iterator it = m_mr_map.find(pair_void_size_t(addr, length));
	if (unlikely(it != m_mr_map.end())) {
		ring_logdbg("memory %p is already registered with length %zd",
			    addr, length);
		lkey = it->second.first;
		it->second.second++;
		return 0;
	}
	lkey = m_p_ib_ctx->mem_reg(addr, length, VMA_IBV_ACCESS_LOCAL_WRITE);
	if (lkey == (uint32_t)-1) {
		ring_logdbg("failed registering MR");
		return -1;
	}
	ring_logdbg("registered memory as lkey:%u addr ptr %p length %zd",
			lkey, addr, length);
	m_mr_map[pair_void_size_t(addr, length)] = pair_mr_ref_t(lkey, 1);
	return 0;
}

int ring_eth_direct::dereg_mr(void *addr, size_t length)
{
	auto_unlocker lock(m_lock_ring_tx);
	pair_void_size_t p(addr, length);

	addr_len_mr_map_t::iterator it = m_mr_map.find(p);
	if (unlikely(it == m_mr_map.end())) {
		ring_logdbg("could not find mr in map, addr is %p, length is %zd",
				addr, length);
		return -1;
	}
	if (it->second.second > 1) {
		it->second.second--;
		ring_logdbg("decreased ref count to %d",it->second.second);
		return 0;
	}
	uint32_t lkey = it->second.first;
	ring_logdbg("deregistered memory as lkey:%u addr %p length %zd",
			lkey, addr, length);
	m_p_ib_ctx->mem_dereg(lkey);
	m_mr_map.erase(p);
	return 0;
}

ring_eth_direct::~ring_eth_direct()
{
	addr_len_mr_map_t::iterator it = m_mr_map.begin();

	for (;it != m_mr_map.end();it++) {
		ring_logwarn("resource leak! registered memory was not released,"
				" addr %p, lenght %zd",it->first.first,
				it->first.second);
	}
	m_mr_map.clear();
}

