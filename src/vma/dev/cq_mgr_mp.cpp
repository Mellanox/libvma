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

#include <dev/cq_mgr_mp.h>

#define MODULE_NAME 		"cqm"

#define cq_logpanic 		__log_info_panic
#define cq_logerr		__log_info_err
#define cq_logwarn		__log_info_warn
#define cq_loginfo		__log_info_info
#define cq_logdbg		__log_info_dbg
#define cq_logfunc		__log_info_func
#define cq_logfuncall		__log_info_funcall
#define cq_logfine		__log_info_fine


#ifdef HAVE_INFINIBAND_MLX5_HW_H

cq_mgr_mp::cq_mgr_mp(ring_eth_mp *p_ring, ib_ctx_handler *p_ib_ctx_handler,
		     uint32_t cq_size,
		     struct ibv_comp_channel *p_comp_event_channel,
		     bool is_rx, int stride_size):
		     cq_mgr_mlx5((ring_simple*)p_ring, p_ib_ctx_handler,
			    cq_size , p_comp_event_channel, is_rx, false),
		     m_p_ring(p_ring)
{
	// must call from derive in order to call derived hooks
	m_pow_stride_size = (1 << stride_size);
	configure(cq_size);
	set_cq();
}

void cq_mgr_mp::prep_ibv_cq(vma_ibv_cq_init_attr &attr)
{
	cq_mgr::prep_ibv_cq(attr);
	attr.comp_mask |= IBV_EXP_CQ_INIT_ATTR_RES_DOMAIN;
	attr.res_domain = m_p_ring->get_res_domain();
}

void cq_mgr_mp::add_qp_rx(qp_mgr *_qp)
{
	cq_logdbg("qp_mgr=%p", _qp);
	struct verbs_qp *vqp = (struct verbs_qp *)_qp->m_qp;
	struct mlx5_qp * mlx5_hw_qp = (struct mlx5_qp*)
			container_of(vqp, struct mlx5_qp, verbs_qp);
	m_rq = &(mlx5_hw_qp->rq);

	m_p_rq_wqe_idx_to_wrid = _qp->m_rq_wqe_idx_to_wrid;
	m_p_cq_stat->n_rx_drained_at_once_max = 0;
	qp_mgr_mp* qp = (qp_mgr_mp *)_qp;
	if (qp->post_recv(0, qp->get_wq_count()) != 0) {
		cq_logdbg("qp post recv failed");
	}

	cq_logdbg("Successfully post_recv qp with %d new Rx buffers",
		  qp->get_wq_count());
}

enum {
	/* Masks to handle the CQE byte_count field in case of MP RQ */
	MP_RQ_BYTE_CNT_FIELD_MASK = 0x0000FFFF,
	MP_RQ_NUM_STRIDES_FIELD_MASK = 0x7FFF0000,
	MP_RQ_FILLER_FIELD_MASK = 0x80000000,
	MP_RQ_NUM_STRIDES_FIELD_SHIFT = 16,
};

/**
 * this function
 *
 *
 * flags is based on struct ibv_exp_cq_family_flags, with the addion of
 * filler bit equal to VMA_MP_RQ_FILLER_CQE
 */
int cq_mgr_mp::poll_mp_cq(uint16_t &size, uint16_t &strides_used,
			  uint32_t &offset, uint32_t &flags,
			  volatile struct mlx5_cqe64 *&cqe64)
{
	volatile struct mlx5_cqe64 *cqe;
	volatile struct mlx5_cqe64 *cqes;

	cqes = *m_cqes;
	cqe = &cqes[m_cq_cons_index & (m_cq_size - 1)];
	uint8_t op_own = cqe->op_own;

	if (unlikely((op_own & MLX5_CQE_OWNER_MASK) == !(m_cq_cons_index & m_cq_size))) {
		return 0;
	} else if (unlikely(op_own & 0x80)) {
		check_error_completion(op_own);
		return -1;
	}
	if (likely(cqe)) {
		cqe64 = cqe;
		int ret = 0;
		uint32_t byte_strides = ntohl(cqe->byte_cnt);
		if (likely(!(byte_strides & MP_RQ_FILLER_FIELD_MASK))) {
			size = byte_strides & MP_RQ_BYTE_CNT_FIELD_MASK;
			strides_used = (byte_strides & MP_RQ_NUM_STRIDES_FIELD_MASK) >>
					MP_RQ_NUM_STRIDES_FIELD_SHIFT;
			offset = ntohs(cqe->wqe_counter) * m_pow_stride_size;
			uint8_t l3_hdr = (cqe->l4_hdr_type_etc) & MLX5_CQE_L3_HDR_TYPE_MASK;
			uint8_t l4_hdr = (cqe->l4_hdr_type_etc) & MLX5_CQE_L4_HDR_TYPE_MASK;
			flags = (!!(cqe->hds_ip_ext & MLX5_CQE_L4_OK) * IBV_EXP_CQ_RX_TCP_UDP_CSUM_OK) |
				(!!(cqe->hds_ip_ext & MLX5_CQE_L3_OK) * IBV_EXP_CQ_RX_IP_CSUM_OK) |
				((l3_hdr == MLX5_CQE_L3_HDR_TYPE_IPV4) * IBV_EXP_CQ_RX_IPV4_PACKET) |
				// RAFI currently only udp is used
//				(((l4_hdr == MLX5_CQE_L4_HDR_TYPE_TCP) || (l4_hdr == MLX5_CQE_L4_HDR_TYPE_TCP_EMP_ACK) ||
//				  (l4_hdr == MLX5_CQE_L4_HDR_TYPE_TCP_ACK)) * IBV_EXP_CQ_RX_TCP_PACKET) |
				((l4_hdr == MLX5_CQE_L4_HDR_TYPE_UDP) * IBV_EXP_CQ_RX_UDP_PACKET);
		} else {
			flags = VMA_MP_RQ_FILLER_CQE;
			ret = 2;
			// optimize checks in ring by setting size non zero
			size = -1;

		}
		prefetch((void*)&(*m_cqes)[m_cq_cons_index & (m_cq_size - 1)]);
//		prefetch((void*)&());// add to the buffer RAFI

		m_cq_cons_index++;
		wmb();
		*m_cq_dbell = htonl(m_cq_cons_index);
		m_rq->tail++;
		cq_logfine("returning packet size %d, stride used %d offset %u "
			   "flags %d", size, strides_used, offset, flags);
		return ret;
	}
	return 0;

}


cq_mgr_mp::~cq_mgr_mp()
{
	m_skip_dtor = true;
}
#endif //HAVE_INFINIBAND_MLX5_HW_H

