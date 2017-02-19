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

#undef  MODULE_NAME
#define MODULE_NAME 		"qpm_mlx5"

#include "qp_mgr_eth_mlx5.h"

#if !defined(DEFINED_VMAPOLL) && defined(HAVE_INFINIBAND_MLX5_HW_H)

#include <sys/mman.h>
#include "cq_mgr_mlx5.h"
#include "vma/util/utils.h"
#include "vlogger/vlogger.h"
#define qp_logerr __log_info_err

qp_mgr_eth_mlx5::qp_mgr_eth_mlx5(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num,
		struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t vlan) throw (vma_error):
		qp_mgr_eth(p_ring, p_context, port_num, p_rx_comp_event_channel, tx_num_wr, vlan, false) {
	if(configure(p_rx_comp_event_channel)) {
		throw_vma_exception("failed creating qp_mgr_eth");
	}
}

qp_mgr_eth_mlx5::~qp_mgr_eth_mlx5()
{
	if (m_rq_wqe_idx_to_wrid) {
		if (0 != munmap(m_rq_wqe_idx_to_wrid, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid))) {
			qp_logerr("Failed deallocating memory with munmap m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
		}

		m_rq_wqe_idx_to_wrid = NULL;
	}
}

cq_mgr* qp_mgr_eth_mlx5::init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel)
{
	m_rx_num_wr = align32pow2(m_rx_num_wr);

	m_rq_wqe_idx_to_wrid = (uint64_t*)mmap(NULL, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (m_rq_wqe_idx_to_wrid == MAP_FAILED) {
		qp_logerr("Failed allocating m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
		return NULL;
	}

	return new cq_mgr_mlx5(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr, p_rx_comp_event_channel, true);
}
#endif
