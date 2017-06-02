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
#include "qp_mgr_eth_mlx5.h"

#if defined(HAVE_INFINIBAND_MLX5_HW_H)

#include <sys/mman.h>
#include "vma/hw/mlx5/wqe.h"
#include "cq_mgr_mlx5.h"
#include "vma/util/utils.h"
#include "vlogger/vlogger.h"
#include "ring_simple.h"

#undef  MODULE_NAME
#define MODULE_NAME 	"qpm_mlx5"
#define qp_logpanic 	__log_info_panic
#define qp_logerr	__log_info_err
#define qp_logwarn	__log_info_warn
#define qp_loginfo	__log_info_info
#define qp_logdbg	__log_info_dbg
#define qp_logfunc	__log_info_func
#define qp_logfuncall	__log_info_funcall

static inline uint64_t align_to_octoword_up(uint64_t val)
{
	return ((val+16-1)>>4)<<4;
}

static inline uint64_t align_to_WQEBB_up(uint64_t val)
{
	return ((val+4-1)>>2)<<2;
}

static inline uint8_t* align_ptr_up(uint8_t* ptr)
{
	return (uint8_t *)align_to_octoword_up((uint64_t)ptr);
}

//
void qp_mgr_eth_mlx5::init_sq()
{
	struct verbs_qp *vqp = (struct verbs_qp *)m_qp;
	m_hw_qp = (struct mlx5_qp*)container_of(vqp, struct mlx5_qp, verbs_qp);
	m_qp_num	 = m_hw_qp->ctrl_seg.qp_num;
	m_sq_wqes	 = (struct mlx5_wqe64 (*)[])(uintptr_t)m_hw_qp->gen_data.sqstart;
	m_sq_wqe_hot	 = &(*m_sq_wqes)[0];
	m_sq_wqes_end	 = (uint8_t*)m_hw_qp->gen_data.sqend;

	m_sq_db		 = &m_hw_qp->gen_data.db[MLX5_SND_DBR];
	m_sq_bf_reg	 = m_hw_qp->gen_data.bf->reg;
	m_sq_bf_buf_size = m_hw_qp->gen_data.bf->buf_size;

	m_sq_wqe_hot_index = 0;
	m_sq_bf_offset	 = m_hw_qp->gen_data.bf->offset;
/*
 * Preliminary fill WQE for completetion request
 * TODO: temporary - exclude for dynamic WQE
 */
	unsigned int comp = NUM_TX_WRE_TO_SIGNAL_MAX;

	for (uint32_t i = 0; i < m_tx_num_wr; ++i) {
		volatile struct mlx5_wqe64 *wqe = &(*m_sq_wqes)[i];

		memset((void *)(uintptr_t)wqe, 0, sizeof(struct mlx5_wqe64));
		wqe->eseg.inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);
		wqe->eseg.cs_flags = MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
		wqe->ctrl.data[1] = htonl((m_qp_num << 8) | 4);
		//wqe->dseg.lkey = (m_p_ring->get_lkey());
		/* Store the completion request in the WQE. */
		if (--comp == 0) {
			wqe->ctrl.data[2] = htonl(8);
			comp = NUM_TX_WRE_TO_SIGNAL_MAX;
		}
		else
			wqe->ctrl.data[2] = 0;
	}

	qp_logfunc("%p allocated for %d QPs sq_wqes:%p sq_wqes_end: %p and configured %d WRs BlueFlame: %p buf_size: %d offset: %d",
			m_qp, m_qp_num, m_sq_wqes, m_sq_wqes_end,  m_tx_num_wr, m_sq_bf_reg, m_sq_bf_buf_size, m_sq_bf_offset);
}

qp_mgr_eth_mlx5::qp_mgr_eth_mlx5(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num,
		struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t vlan) throw (vma_error):
	qp_mgr_eth(p_ring, p_context, port_num, p_rx_comp_event_channel, tx_num_wr, vlan, false)
	,m_hw_qp(NULL)
	,m_sq_wqe_idx_to_wrid(NULL)
	,m_sq_wqes(NULL)
	,m_sq_wqe_hot(NULL)
	,m_sq_wqes_end(NULL)
	,m_sq_db(NULL)
	,m_sq_bf_reg(NULL)
	,m_qp_num(0)
	,m_sq_wqe_hot_index(0)
	,m_sq_bf_offset(0)
	,m_sq_bf_buf_size(0)
	,m_sq_wqe_counter(0)
{
	if(configure(p_rx_comp_event_channel)) {
		throw_vma_exception("failed creating qp_mgr_eth");
	}

	init_sq();

	if (m_p_cq_mgr_tx) {
		m_p_cq_mgr_tx->add_qp_tx(this);
	}

	qp_logfunc("cq_mgr_tx= %p", m_p_cq_mgr_tx);

}

qp_mgr_eth_mlx5::~qp_mgr_eth_mlx5()
{
	if (m_rq_wqe_idx_to_wrid) {
		if (0 != munmap(m_rq_wqe_idx_to_wrid, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid))) {
			qp_logerr("Failed deallocating memory with munmap m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
		}

		m_rq_wqe_idx_to_wrid = NULL;
	}
	if (m_sq_wqe_idx_to_wrid) {
		if (0 != munmap(m_sq_wqe_idx_to_wrid, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_wrid))) {
			qp_logerr("Failed deallocating memory with munmap m_sq_wqe_idx_to_wrid (errno=%d %m)", errno);
		}

		m_sq_wqe_idx_to_wrid = NULL;
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
#ifdef DEFINED_VMAPOLL
	return new cq_mgr(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr, p_rx_comp_event_channel, true);
#else
	return new cq_mgr_mlx5(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr, p_rx_comp_event_channel, true);
#endif
}

cq_mgr* qp_mgr_eth_mlx5::init_tx_cq_mgr()
{
	return new cq_mgr_mlx5(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr, m_p_ring->get_tx_comp_event_channel(), false);
}

inline void qp_mgr_eth_mlx5::set_signal_in_next_send_wqe()
{
	volatile struct mlx5_wqe64 *wqe = &(*m_sq_wqes)[m_sq_wqe_counter & (m_tx_num_wr - 1)];
	wqe->ctrl.data[2] = htonl(8);
}

static inline void mlx5_bf_copy(volatile uintptr_t *dst, volatile uintptr_t *src)
{
	COPY_64B_NT(dst, src);
}

int qp_mgr_eth_mlx5::send_to_wire(vma_ibv_send_wr *p_send_wqe)
{
	uintptr_t addr = 0;
	uint32_t length = 0;
	uint32_t lkey = 0;

	addr = p_send_wqe->sg_list[0].addr;
	length = p_send_wqe->sg_list[0].length;
	lkey = p_send_wqe->sg_list[0].lkey;

	/* Copy the first bytes into the inline header */
	/* This suppress warning due to mlx5_wqe_eth_seg struct format as
	* uint8_t inline_hdr_start[2];
	* uint8_t inline_hdr[16];
	*/
	/* coverity[buffer_size] */
	/* coverity[overrun-buffer-arg] */
	memcpy((void *)m_sq_wqe_hot->eseg.inline_hdr_start,
		(void *)addr, MLX5_ETH_INLINE_HEADER_SIZE);

	addr += MLX5_ETH_INLINE_HEADER_SIZE;
	length -= MLX5_ETH_INLINE_HEADER_SIZE;

	m_sq_wqe_hot->dseg.byte_count = htonl(length);
	m_sq_wqe_hot->dseg.lkey = htonl(lkey);
	m_sq_wqe_hot->dseg.addr = htonll(addr);

	++m_sq_wqe_cntr;

	/*
	* Make sure that descriptors are written before
	* updating doorbell record and ringing the doorbell
	*/
	wmb();
	*m_sq_db = htonl(m_sq_wqe_cntr);
	/* This wc_wmb ensures ordering between DB record and BF copy */
        wc_wmb();

	/*
	 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
	 * implementations may use move-string-buffer assembler instructions,
	 * which do not guarantee order of copying.
	 */
	mlx5_bf_copy((volatile uintptr_t *)((uintptr_t)m_sq_bf_reg + m_sq_bf_offset),
		     (volatile uintptr_t *)m_sq_wqe_hot);
	m_sq_bf_offset ^= m_sq_bf_buf_size;
        m_sq_wqe_idx_to_wrid[m_sq_wqe_hot_index] = (uintptr_t)p_send_wqe->wr_id;

	/*Set the next WQE and index*/
	m_sq_wqe_hot = &(*m_sq_wqes)[m_sq_wqe_cntr & (m_tx_num_wr - 1)];
	/* Write only data[0] which is the single element which changes.
	 * Other fields are already initialised in mlx5_init_sq. */
	m_sq_wqe_hot->ctrl.data[0] = htonl((m_sq_wqe_cntr << 8) | MLX5_OPCODE_SEND);
	m_sq_wqe_hot_index = m_sq_wqe_cntr & (m_tx_num_wr - 1);

	return 0;
}

//! Handle releasing of Tx buffers
//  Single post send with SIGNAL of a dummy packet

// NOTE: Since the QP is in ERROR state no packets will be sent on the wire!
// So we can post_send anything we want :)
void qp_mgr_eth_mlx5::trigger_completion_for_all_sent_packets()
{
	qp_logfunc("unsignaled count=%d, last=%p", m_n_unsignaled_count, m_p_last_tx_mem_buf_desc);

	if (m_p_last_tx_mem_buf_desc) { // Meaning that there is at least one post_send in the QP mem_buf_desc that wasn't signaled for completion
		qp_logdbg("Need to send closing tx wr...");
		// Allocate new send buffer
		mem_buf_desc_t* p_mem_buf_desc = m_p_ring->mem_buf_tx_get(0, true);
		m_p_ring->m_missing_buf_ref_count--; // Align Tx buffer accounting since we will be bypassing the normal send calls
		if (!p_mem_buf_desc) {
			qp_logerr("no buffer in pool");
			return;
		}
		p_mem_buf_desc->p_next_desc = m_p_last_tx_mem_buf_desc;

		// Prepare dummy packet: zeroed payload ('0000').
		// For ETH it replaces the MAC header!! (Nothing is going on the wire, QP in error state)
		/* need to send at least eth+ip, since libmlx5 will drop just eth header */
		ethhdr* p_buffer_ethhdr = (ethhdr *)p_mem_buf_desc->p_buffer;
		memset(p_buffer_ethhdr, 0, sizeof(*p_buffer_ethhdr));
		p_buffer_ethhdr->h_proto = htons(ETH_P_IP);
		iphdr* p_buffer_iphdr = (iphdr *)(p_mem_buf_desc->p_buffer + sizeof(*p_buffer_ethhdr));
		memset(p_buffer_iphdr, 0, sizeof(*p_buffer_iphdr));

		ibv_sge sge[1];
		sge[0].length = sizeof(ethhdr) + sizeof(iphdr);
		sge[0].addr = (uintptr_t)(p_mem_buf_desc->p_buffer);
		sge[0].lkey = m_p_ring->m_tx_lkey;

		// Prepare send wr for (does not care if it is UD/IB or RAW/ETH)
		// UD requires AH+qkey, RAW requires minimal payload instead of MAC header.
		vma_ibv_send_wr send_wr;

		memset(&send_wr, 0, sizeof(send_wr));
		send_wr.wr_id = (uintptr_t)p_mem_buf_desc;
		send_wr.wr.ud.ah = NULL;
		send_wr.sg_list = sge;
		send_wr.num_sge = 1;
		send_wr.next = NULL;
		vma_send_wr_opcode(send_wr) = VMA_IBV_WR_SEND;
		vma_send_wr_send_flags(send_wr) = (vma_ibv_send_flags)(VMA_IBV_SEND_SIGNALED /*| VMA_IBV_SEND_INLINE*/); //todo inline only if inline is on

		// Close the Tx unsignaled send list
		set_unsignaled_count();
		m_p_last_tx_mem_buf_desc = NULL;

		if (!m_p_ring->m_tx_num_wr_free) {
			qp_logdbg("failed to trigger completion for all packets due to no available wr");
			return;
		}
		m_p_ring->m_tx_num_wr_free--;

		set_signal_in_next_send_wqe();
		send_to_wire(&send_wr);
	}
}

#endif

