/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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

#include "dev/cq_mgr_mp.h"
#include "dev/cq_mgr_mlx5.inl"
#include "dev/qp_mgr_mp.h"

#define MODULE_NAME 		"cqm"

#define cq_logpanic 		__log_info_panic
#define cq_logerr		__log_info_err
#define cq_logwarn		__log_info_warn
#define cq_loginfo		__log_info_info
#define cq_logdbg		__log_info_dbg
#define cq_logfunc		__log_info_func
#define cq_logfuncall		__log_info_funcall
#define cq_logfine		__log_info_fine


#ifdef HAVE_MP_RQ

#define MLX5_CQE_UDP_IP_CSUM_OK(cqe) \
	((!!((cqe)->hds_ip_ext & MLX5_CQE_L4_OK) * IBV_EXP_CQ_RX_TCP_UDP_CSUM_OK) | \
	(!!((cqe)->hds_ip_ext & MLX5_CQE_L3_OK) * IBV_EXP_CQ_RX_IP_CSUM_OK))

enum {
	/* Masks to handle the CQE byte_count field in case of MP RQ */
	MP_RQ_BYTE_CNT_FIELD_MASK = 0x0000FFFF,
	MP_RQ_NUM_STRIDES_FIELD_MASK = 0x7FFF0000,
	MP_RQ_FILLER_FIELD_MASK = 0x80000000,
	MP_RQ_NUM_STRIDES_FIELD_SHIFT = 16,
};

// for optimization expected checksum for receiving packets
const uint32_t cq_mgr_mp::UDP_OK_FLAGS = IBV_EXP_CQ_RX_IP_CSUM_OK |
					 IBV_EXP_CQ_RX_TCP_UDP_CSUM_OK;

cq_mgr_mp::cq_mgr_mp(const ring_eth_cb *p_ring, ib_ctx_handler *p_ib_ctx_handler,
		     uint32_t cq_size,
		     struct ibv_comp_channel *p_comp_event_channel,
		     bool is_rx):
		     cq_mgr_mlx5((ring_simple*)p_ring, p_ib_ctx_handler,
				 cq_size , p_comp_event_channel, is_rx, false),
		     m_p_ring(p_ring)
{
	// must call from derive in order to call derived hooks
	m_p_cq_stat->n_buffer_pool_len = cq_size;
	m_p_cq_stat->n_rx_drained_at_once_max = 0;
	configure(cq_size);
}

void cq_mgr_mp::prep_ibv_cq(vma_ibv_cq_init_attr &attr) const
{
	cq_mgr::prep_ibv_cq(attr);
	attr.comp_mask |= IBV_EXP_CQ_INIT_ATTR_RES_DOMAIN;
	attr.res_domain = m_p_ring->get_res_domain();
}

void cq_mgr_mp::add_qp_rx(qp_mgr *qp)
{
	cq_logdbg("qp_mp_mgr=%p", qp);
	qp_mgr_mp* mp_qp = dynamic_cast<qp_mgr_mp *>(qp);

	if (mp_qp == NULL) {
		cq_logdbg("this qp is not of type qp_mgr_mp %p", qp);
		throw_vma_exception("this qp is not of type qp_mgr_mp");
	}
	set_qp_rq(qp);
	m_qp_rec.qp = qp;
	if (mp_qp->post_recv(0, mp_qp->get_wq_count()) != 0) {
		cq_logdbg("qp post recv failed");
	} else {
		cq_logdbg("Successfully post_recv qp with %d new Rx buffers",
			  mp_qp->get_wq_count());
	}
}

/**
 * this function polls the CQ, and extracts the needed fields
 * upon CQE error state it will return -1
 * if a bad checksum packet or a filler bit it will return VMA_MP_RQ_BAD_PACKET
 */
int cq_mgr_mp::poll_mp_cq(uint16_t &size, uint32_t &strides_used,
			  uint32_t &flags, volatile struct mlx5_cqe64 *&out_cqe64)
{
	volatile struct mlx5_cqe64 *cqe= check_cqe();
	if (likely(cqe)) {
		if (unlikely(MLX5_CQE_OPCODE(cqe->op_own) != MLX5_CQE_RESP_SEND)) {
			cq_logdbg("Warning op_own is %x", MLX5_CQE_OPCODE(cqe->op_own));
			// optimize checks in ring by setting size non zero
			size = 1;
			m_p_cq_stat->n_rx_pkt_drop++;
			return -1;
		}
		m_p_cq_stat->n_rx_pkt_drop += cqe->sop_qpn.sop;
		out_cqe64 = cqe;
		uint32_t stride_byte_cnt = ntohl(cqe->byte_cnt);
		strides_used += (stride_byte_cnt & MP_RQ_NUM_STRIDES_FIELD_MASK) >>
				MP_RQ_NUM_STRIDES_FIELD_SHIFT;
		if (unlikely((stride_byte_cnt & MP_RQ_FILLER_FIELD_MASK) ||
			     ((flags = MLX5_CQE_UDP_IP_CSUM_OK(cqe)) != UDP_OK_FLAGS))) {
			flags |= VMA_MP_RQ_BAD_PACKET;
			size = 1; // optimize
		} else {
			out_cqe64 = cqe;
			size = stride_byte_cnt & MP_RQ_BYTE_CNT_FIELD_MASK;
		}
		++m_cq_cons_index;
		prefetch((void*)&(*m_cqes)[m_cq_cons_index & (m_cq_size - 1)]);
	} else {
		size = 0;
		flags = 0;
	}
	cq_logfine("returning packet size %d, stride used %d "
		   "flags %d", size, strides_used, flags);
	return 0;
}

void cq_mgr_mp::update_dbell()
{
	wmb();
	++m_rq->tail;
	*m_cq_dbell = htonl(m_cq_cons_index & 0xffffff);
}

cq_mgr_mp::~cq_mgr_mp()
{
	volatile struct mlx5_cqe64 *out_cqe64;
	uint16_t size;
	uint32_t strides_used = 0, flags = 0;
	int ret;
	do {
		ret = poll_mp_cq(size, strides_used, flags, out_cqe64);
	} while (size > 0 || ret);
	// prevents seg fault in mlx5 destructor
	m_rq = NULL;
}
#endif // HAVE_MP_RQ

