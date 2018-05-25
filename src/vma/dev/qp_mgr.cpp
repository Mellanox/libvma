/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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

#include "qp_mgr.h"
#include "utils/bullseye.h"
#include "vma/util/utils.h"
#include "vma/util/valgrind.h"
#include "vma/util/instrumentation.h"
#include "vma/iomux/io_mux_call.h"
#include "buffer_pool.h"
#include "cq_mgr.h"
#include "ring_simple.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"qpm"

#define qp_logpanic 	__log_info_panic
#define qp_logerr	__log_info_err
#define qp_logwarn	__log_info_warn
#define qp_loginfo	__log_info_info
#define qp_logdbg	__log_info_dbg
#define qp_logfunc	__log_info_func
#define qp_logfuncall	__log_info_funcall


//#define ALIGN_WR_UP(_num_wr_) 		(max(32, ((_num_wr_ + 0xf) & ~(0xf))))
#define ALIGN_WR_DOWN(_num_wr_) 		(max(32, ((_num_wr_      ) & ~(0xf))))

#define FICTIVE_REMOTE_QPN	0x48
#define FICTIVE_REMOTE_QKEY	0x01234567
#define FICTIVE_AH_SL		5
#define FICTIVE_AH_DLID		0x3


qp_mgr::qp_mgr(const ring_simple* p_ring, const ib_ctx_handler* p_context,
		const uint8_t port_num, const uint32_t tx_num_wr):
	 m_rq_wqe_counter(0)
	,m_rq_wqe_idx_to_wrid(NULL)
#ifdef DEFINED_SOCKETXTREME
	,m_mlx5_hw_qp(NULL)
#endif
	,m_qp(NULL)
	,m_p_ring((ring_simple*)p_ring)
	,m_port_num((uint8_t)port_num)
	,m_p_ib_ctx_handler((ib_ctx_handler*)p_context)
	,m_p_ahc_head(NULL)
	,m_p_ahc_tail(NULL)
	,m_max_inline_data(0)
	,m_max_qp_wr(0)
	,m_p_cq_mgr_rx(NULL)
	,m_p_cq_mgr_tx(NULL)
	,m_rx_num_wr(safe_mce_sys().rx_num_wr)
	,m_tx_num_wr(tx_num_wr)
	,m_hw_dummy_send_support(false)
	,m_n_sysvar_rx_num_wr_to_post_recv(safe_mce_sys().rx_num_wr_to_post_recv)
	,m_n_sysvar_tx_num_wr_to_signal(safe_mce_sys().tx_num_wr_to_signal)
	,m_n_sysvar_rx_prefetch_bytes_before_poll(safe_mce_sys().rx_prefetch_bytes_before_poll)
	,m_curr_rx_wr(0)
	,m_last_posted_rx_wr_id(0)
	,m_n_unsignaled_count(0)
	,m_p_last_tx_mem_buf_desc(NULL)
	,m_p_prev_rx_desc_pushed(NULL)
	,m_n_ip_id_base(0)
	,m_n_ip_id_offset(0)
{
	m_ibv_rx_sg_array = new ibv_sge[m_n_sysvar_rx_num_wr_to_post_recv];
	m_ibv_rx_wr_array = new ibv_recv_wr[m_n_sysvar_rx_num_wr_to_post_recv];

	set_unsignaled_count();
	memset(&m_rate_limit, 0, sizeof(struct vma_rate_limit_t));

#ifdef DEFINED_SOCKETXTREME
	m_rq_wqe_idx_to_wrid = (uint64_t*)mmap(NULL, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid),
		PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (m_rq_wqe_idx_to_wrid == MAP_FAILED) {
		qp_logerr("Failed allocating m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
	}
#endif // DEFINED_SOCKETXTREME
	qp_logfunc("");
}

qp_mgr::~qp_mgr()
{
	qp_logfunc("");

	// Don't assume anything
	// release_tx/rx_buffers() - poll and process the CQ's
	release_tx_buffers();
	release_rx_buffers();

	if (m_p_cq_mgr_rx) {
		m_p_cq_mgr_rx->clean_cq();
	}
	qp_logdbg("calling ibv_destroy_qp(qp=%p)", m_qp);
	if (m_qp) {
		IF_VERBS_FAILURE_EX(ibv_destroy_qp(m_qp), EIO) {
			qp_logdbg("QP destroy failure (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_qp, sizeof(ibv_qp));
	}
	m_qp = NULL;

	if (m_p_cq_mgr_tx) {
		delete m_p_cq_mgr_tx;
		m_p_cq_mgr_tx = NULL;
	}
	if (m_p_cq_mgr_rx) {
		delete m_p_cq_mgr_rx;
		m_p_cq_mgr_rx = NULL;
	}

	delete[] m_ibv_rx_sg_array;
	delete[] m_ibv_rx_wr_array;

#ifdef DEFINED_SOCKETXTREME
        if (m_rq_wqe_idx_to_wrid) {
		if (0 != munmap(m_rq_wqe_idx_to_wrid, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid))) {
			qp_logerr("Failed deallocating memory with munmap m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
		}
		m_rq_wqe_idx_to_wrid = NULL;
	}
#endif // DEFINED_SOCKETXTREME

	qp_logdbg("Rx buffer poll: %d free global buffers available", g_buffer_pool_rx->get_free_count());
	qp_logdbg("delete done");
}

cq_mgr* qp_mgr::init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel)
{
	qp_logfunc("");
	return new cq_mgr(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr, p_rx_comp_event_channel, true);
}

cq_mgr* qp_mgr::init_tx_cq_mgr()
{
	qp_logfunc("");
	return new cq_mgr(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr, m_p_ring->get_tx_comp_event_channel(), false);
}

int qp_mgr::configure(struct ibv_comp_channel* p_rx_comp_event_channel)
{
	qp_logdbg("Creating QP of transport type '%s' on ibv device '%s' [%p] on port %d",
			priv_vma_transport_type_str(m_p_ring->get_transport_type()),
			m_p_ib_ctx_handler->get_ibname(), m_p_ib_ctx_handler->get_ibv_device(), m_port_num);

	vma_ibv_device_attr *r_ibv_dev_attr = m_p_ib_ctx_handler->get_ibv_device_attr();

	// Check device capabilities for max QP work requests
	m_max_qp_wr = ALIGN_WR_DOWN(r_ibv_dev_attr->max_qp_wr - 1);
	if (m_rx_num_wr > m_max_qp_wr) {
		qp_logwarn("Allocating only %d Rx QP work requests while user "
			   "requested %s=%d for QP on <%p, %d>",
			   m_max_qp_wr, SYS_VAR_RX_NUM_WRE, m_rx_num_wr,
			   m_p_ib_ctx_handler, m_port_num);
		m_rx_num_wr = m_max_qp_wr;
	}

	// Check device capabilities for dummy send support
#ifdef DEFINED_IBV_EXP_WR_NOP
	m_hw_dummy_send_support = r_ibv_dev_attr->exp_device_cap_flags & IBV_EXP_DEVICE_NOP;
#endif
	qp_logdbg("HW Dummy send support for QP = %d", m_hw_dummy_send_support);

	// Create associated Tx & Rx cq_mgrs
	m_p_cq_mgr_tx = init_tx_cq_mgr();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_cq_mgr_tx) {
		qp_logerr("Failed allocating m_p_cq_mgr_tx (errno=%d %m)", errno);
		return -1;
	}
	m_p_cq_mgr_rx = init_rx_cq_mgr(p_rx_comp_event_channel);
	if (!m_p_cq_mgr_rx) {
		qp_logerr("Failed allocating m_p_cq_mgr_rx (errno=%d %m)", errno);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// Modify the Rx and Tx cq_mgr to use a non-blocking event channel
	set_fd_block_mode(m_p_cq_mgr_rx->get_channel_fd(), false);
	set_fd_block_mode(m_p_cq_mgr_tx->get_channel_fd(), false);

	qp_logdbg("cq tx: %p rx: %p", m_p_cq_mgr_tx, m_p_cq_mgr_rx);

	// Create QP
	vma_ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	// Check device capabilities for max SG elements
	uint32_t tx_max_inline = safe_mce_sys().tx_max_inline;
	uint32_t rx_num_sge = (IS_SOCKETXTREME) ? 1 : MCE_DEFAULT_RX_NUM_SGE;
	uint32_t tx_num_sge = MCE_DEFAULT_TX_NUM_SGE;

	qp_init_attr.cap.max_send_wr = m_tx_num_wr;
	qp_init_attr.cap.max_recv_wr = m_rx_num_wr;
	qp_init_attr.cap.max_inline_data = tx_max_inline;
	qp_init_attr.cap.max_send_sge = tx_num_sge;
	qp_init_attr.cap.max_recv_sge = rx_num_sge;
	qp_init_attr.recv_cq = m_p_cq_mgr_rx->get_ibv_cq_hndl();
	qp_init_attr.send_cq = m_p_cq_mgr_tx->get_ibv_cq_hndl();
	qp_init_attr.sq_sig_all = 0;

	// Create the QP
	if (prepare_ibv_qp(qp_init_attr)) {
		return -1;
	}

	// All buffers will be allocated from this qp_mgr buffer pool so we can already set the Rx & Tx lkeys
	for (uint32_t wr_idx = 0; wr_idx < m_n_sysvar_rx_num_wr_to_post_recv; wr_idx++) {
		m_ibv_rx_wr_array[wr_idx].sg_list = &m_ibv_rx_sg_array[wr_idx];
		m_ibv_rx_wr_array[wr_idx].num_sge = 1;
		m_ibv_rx_wr_array[wr_idx].next = &m_ibv_rx_wr_array[wr_idx+1]; // pre-define the linked list
	}
	m_ibv_rx_wr_array[m_n_sysvar_rx_num_wr_to_post_recv-1].next = NULL; // end linked list

	m_curr_rx_wr = 0;

	m_p_ahc_head = NULL;
	m_p_ahc_tail = NULL;

#ifdef DEFINED_SOCKETXTREME
	struct verbs_qp *vqp = (struct verbs_qp *)m_qp;
	m_mlx5_hw_qp = (struct mlx5_qp*)container_of(vqp, struct mlx5_qp, verbs_qp);
#endif //DEFINED_SOCKETXTREME
	if (m_p_cq_mgr_tx) {
		m_p_cq_mgr_tx->add_qp_tx(this);
	}

	qp_logdbg("Created QP (num=%d) with %d tx wre and inline=%d and %d rx "
		"wre and %d sge", m_qp->qp_num, m_tx_num_wr, m_max_inline_data,
		m_rx_num_wr, rx_num_sge);
	return 0;
}

void qp_mgr::up()
{
	// Add buffers
	qp_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_qp));
	release_rx_buffers(); // We might have old flushed cqe's in our CQ still from previous HA event
	release_tx_buffers();

	/* clean any link to completions with error we might have */
	set_unsignaled_count();
	m_p_last_tx_mem_buf_desc = NULL;

	modify_qp_to_ready_state();
	m_p_cq_mgr_rx->add_qp_rx(this);
}

void qp_mgr::down()
{
	qp_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_qp));
	modify_qp_to_error_state();

	// free buffers from current active resource iterator
	trigger_completion_for_all_sent_packets();

	// let the QP drain all wqe's to flushed cqe's now that we moved 
	// it to error state and post_sent final trigger for completion
	usleep(1000);

	release_tx_buffers();
	release_rx_buffers();
	m_p_cq_mgr_rx->del_qp_rx(this);
}

void qp_mgr::modify_qp_to_error_state()
{
	qp_logdbg("");

	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_ibv_modify_qp_to_err(m_qp)) {
		qp_logdbg("ibv_modify_qp failure (errno = %d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

void qp_mgr::release_rx_buffers()
{
	int total_ret = m_curr_rx_wr;
	if (m_curr_rx_wr) {
		qp_logdbg("Returning %d pending post_recv buffers to CQ owner", m_curr_rx_wr);
		while (m_curr_rx_wr) {
			--m_curr_rx_wr;
			mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(uintptr_t)m_ibv_rx_wr_array[m_curr_rx_wr].wr_id;
			if (p_mem_buf_desc && p_mem_buf_desc->p_desc_owner) {
				p_mem_buf_desc->p_desc_owner->mem_buf_desc_return_to_owner_rx(p_mem_buf_desc);
			}
			else {
				g_buffer_pool_rx->put_buffers_thread_safe(p_mem_buf_desc);
			}
		}
	}
	// Wait for all FLUSHed WQE on Rx CQ
	qp_logdbg("draining rx cq_mgr %p (last_posted_rx_wr_id = %p)", m_p_cq_mgr_rx, m_last_posted_rx_wr_id);
	uintptr_t last_polled_rx_wr_id = 0;
	while (m_p_cq_mgr_rx && last_polled_rx_wr_id != m_last_posted_rx_wr_id) {

		// Process the FLUSH'ed WQE's
		int ret = m_p_cq_mgr_rx->drain_and_proccess(&last_polled_rx_wr_id);
		qp_logdbg("draining completed on rx cq_mgr (%d wce) last_polled_rx_wr_id = %p", ret, last_polled_rx_wr_id);
		total_ret += ret;

		// Add short delay (500 usec) to allow for WQE's to be flushed to CQ every poll cycle
		const struct timespec short_sleep = {0, 500000}; // 500 usec
		nanosleep(&short_sleep, NULL);
	}
	m_last_posted_rx_wr_id = 0; // Clear the posted WR_ID flag, we just clear the entier RQ
	qp_logdbg("draining completed with a total of %d wce's on rx cq_mgr", total_ret);
}

void qp_mgr::release_tx_buffers()
{
	int ret = 0;
	uint64_t poll_sn;
	qp_logdbg("draining tx cq_mgr %p", m_p_cq_mgr_tx);
	while (m_p_cq_mgr_tx && (ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn)) > 0) {
		qp_logdbg("draining completed on tx cq_mgr (%d wce)", ret);
	}
}

void qp_mgr::trigger_completion_for_all_sent_packets()
{
	vma_ibv_send_wr send_wr;
	ibv_sge sge[1];

	// Handle releasing of Tx buffers
	// Single post send with SIGNAL of a dummy packet

	// NOTE: Since the QP is in ERROR state no packets will be sent on the wire!
	// So we can post_send anything we want :)

	qp_logdbg("unsignaled count=%d, last=%p", m_n_unsignaled_count, m_p_last_tx_mem_buf_desc);
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
		// For IB it replaces the IPoIB header.

		/* need to send at least eth+ip, since libmlx5 will drop just eth header */
		ethhdr* p_buffer_ethhdr = (ethhdr *)p_mem_buf_desc->p_buffer;
		memset(p_buffer_ethhdr, 0, sizeof(*p_buffer_ethhdr));
		p_buffer_ethhdr->h_proto = htons(ETH_P_IP);
		iphdr* p_buffer_iphdr = (iphdr *)(p_mem_buf_desc->p_buffer + sizeof(*p_buffer_ethhdr));
		memset(p_buffer_iphdr, 0, sizeof(*p_buffer_iphdr));
		sge[0].length = sizeof(ethhdr) + sizeof(iphdr);
		sge[0].addr = (uintptr_t)(p_mem_buf_desc->p_buffer);
		sge[0].lkey = m_p_ring->m_tx_lkey;

		struct ibv_ah *p_ah = NULL;
		ibv_ah_attr ah_attr;

		if (m_p_ring->get_transport_type() == VMA_TRANSPORT_IB) {
			memset(&ah_attr, 0, sizeof(ah_attr));
			ah_attr.dlid	=	FICTIVE_AH_DLID;
			ah_attr.sl	=	FICTIVE_AH_SL;
			ah_attr.src_path_bits	= 0;
			ah_attr.static_rate	= 0;
			ah_attr.is_global	= 0;
			ah_attr.port_num	= m_port_num; // Do we need it?

			p_ah = ibv_create_ah(m_p_ib_ctx_handler->get_ibv_pd(), &ah_attr);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!p_ah) {
				qp_logpanic("failed creating address handler (errno=%d %m)", errno);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}

		// Prepare send wr for (does not care if it is UD/IB or RAW/ETH)
		// UD requires AH+qkey, RAW requires minimal payload instead of MAC header.

		memset(&send_wr, 0, sizeof(send_wr));
		send_wr.wr_id = (uintptr_t)p_mem_buf_desc;
		send_wr.wr.ud.ah = p_ah;
		send_wr.wr.ud.remote_qpn = FICTIVE_REMOTE_QPN;
		send_wr.wr.ud.remote_qkey = FICTIVE_REMOTE_QKEY;
		send_wr.sg_list = sge;
		send_wr.num_sge = 1;
		send_wr.next = NULL;
		vma_send_wr_opcode(send_wr) = VMA_IBV_WR_SEND;
		qp_logdbg("IBV_SEND_SIGNALED");

		// Close the Tx unsignaled send list
		set_unsignaled_count();
		m_p_last_tx_mem_buf_desc = NULL;

		if (!m_p_ring->m_tx_num_wr_free) {
			qp_logdbg("failed to trigger completion for all packets due to no available wr");
			return;
		}
		m_p_ring->m_tx_num_wr_free--;

		send_to_wire(&send_wr, (vma_wr_tx_packet_attr)(VMA_TX_PACKET_L3_CSUM|VMA_TX_PACKET_L4_CSUM), true);
		if (p_ah) {
			IF_VERBS_FAILURE(ibv_destroy_ah(p_ah))
			{
				qp_logpanic("failed destroying address handle (errno=%d %m)", errno);
			}ENDIF_VERBS_FAILURE;
		}
	}
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

void qp_mgr::ah_cleanup(struct ibv_ah* ah)
{
	ah_cleaner * curr_ahc = new ah_cleaner(ah, m_p_ring);
	qp_logdbg("insert new ah_cleaner to list");

	if (!m_p_ahc_head) {  // empty list
		m_p_ahc_head = curr_ahc;
	}
	else {
		m_p_ahc_tail->m_next_owner = curr_ahc;
	}
	m_p_ahc_tail = curr_ahc;
	
#if 0
	ah_cleaner* temp_ahc = m_p_ahc_head;
	int i = 1;
	while (temp_ahc) {
		qp_logdbg("ah num %d, ahc =%p ", i, temp_ahc);
		i++;
		temp_ahc = (ah_cleaner*) temp_ahc->m_next_owner;
	}
#endif
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

uint32_t qp_mgr::get_rx_max_wr_num()
{
	return m_rx_num_wr;
}

void qp_mgr::post_recv_buffer(mem_buf_desc_t* p_mem_buf_desc)
{
	if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
		if (m_p_prev_rx_desc_pushed)
			m_p_prev_rx_desc_pushed->p_prev_desc = p_mem_buf_desc;
		m_p_prev_rx_desc_pushed = p_mem_buf_desc;
	}

	m_ibv_rx_wr_array[m_curr_rx_wr].wr_id  = (uintptr_t)p_mem_buf_desc;
	m_ibv_rx_sg_array[m_curr_rx_wr].addr   = (uintptr_t)p_mem_buf_desc->p_buffer;
	m_ibv_rx_sg_array[m_curr_rx_wr].length = p_mem_buf_desc->sz_buffer;
	m_ibv_rx_sg_array[m_curr_rx_wr].lkey   = p_mem_buf_desc->lkey;

	if (m_rq_wqe_idx_to_wrid) {
		uint32_t index = m_rq_wqe_counter & (m_rx_num_wr - 1);
		m_rq_wqe_idx_to_wrid[index] = (uintptr_t)p_mem_buf_desc;
		++m_rq_wqe_counter;
	}

	if (m_curr_rx_wr == m_n_sysvar_rx_num_wr_to_post_recv - 1) {

		m_last_posted_rx_wr_id = (uintptr_t)p_mem_buf_desc;

		m_p_prev_rx_desc_pushed = NULL;
		p_mem_buf_desc->p_prev_desc = NULL;

		m_curr_rx_wr = 0;
		struct ibv_recv_wr *bad_wr = NULL;
		IF_VERBS_FAILURE(ibv_post_recv(m_qp, &m_ibv_rx_wr_array[0], &bad_wr)) {
			uint32_t n_pos_bad_rx_wr = ((uint8_t*)bad_wr - (uint8_t*)m_ibv_rx_wr_array) / sizeof(struct ibv_recv_wr);
			qp_logerr("failed posting list (errno=%d %m)", errno);
			qp_logerr("bad_wr is %d in submitted list (bad_wr=%p, m_ibv_rx_wr_array=%p, size=%d)", n_pos_bad_rx_wr, bad_wr, m_ibv_rx_wr_array, sizeof(struct ibv_recv_wr));
			qp_logerr("bad_wr info: wr_id=%#x, next=%p, addr=%#x, length=%d, lkey=%#x", bad_wr[0].wr_id, bad_wr[0].next, bad_wr[0].sg_list[0].addr, bad_wr[0].sg_list[0].length, bad_wr[0].sg_list[0].lkey);
			qp_logerr("QP current state: %d", priv_ibv_query_qp_state(m_qp));

			// Fix broken linked list of rx_wr
			if (n_pos_bad_rx_wr != (m_n_sysvar_rx_num_wr_to_post_recv - 1)) {
				m_ibv_rx_wr_array[n_pos_bad_rx_wr].next = &m_ibv_rx_wr_array[n_pos_bad_rx_wr+1];
			}
			throw;
		} ENDIF_VERBS_FAILURE;
		qp_logfunc("Successful ibv_post_recv");
	}
	else {
		m_curr_rx_wr++;
	}
}

void qp_mgr::post_recv_buffers(descq_t* p_buffers, size_t count)
{
	qp_logfuncall("");
	// Called from cq_mgr context under cq_mgr::LOCK!
	while (count--) {
		post_recv_buffer(p_buffers->get_and_pop_front());
	}
}

inline int qp_mgr::send_to_wire(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr, bool request_comp)
{
	NOT_IN_USE(attr);
	int ret = 0;
	vma_ibv_send_wr *bad_wr = NULL;

	if (request_comp) {
		vma_send_wr_send_flags(*p_send_wqe) = (vma_ibv_send_flags)(vma_send_wr_send_flags(*p_send_wqe) | VMA_IBV_SEND_SIGNALED);
	}

	IF_VERBS_FAILURE(vma_ibv_post_send(m_qp, p_send_wqe, &bad_wr)) {
		qp_logerr("failed post_send%s (errno=%d %m)\n", ((vma_send_wr_send_flags(*p_send_wqe) & VMA_IBV_SEND_INLINE)?"(+inline)":""), errno);
		if (bad_wr) {
			qp_logerr("bad_wr info: wr_id=%#x, send_flags=%#x, addr=%#x, length=%d, lkey=%#x, max_inline_data=%d",
			bad_wr->wr_id, vma_send_wr_send_flags(*bad_wr), bad_wr->sg_list[0].addr, bad_wr->sg_list[0].length, bad_wr->sg_list[0].lkey, m_max_inline_data);
		}
		ret = -1;
	} ENDIF_VERBS_FAILURE;

	// Clear the SINGAL request
	vma_send_wr_send_flags(*p_send_wqe) = (vma_ibv_send_flags)(vma_send_wr_send_flags(*p_send_wqe) & ~VMA_IBV_SEND_SIGNALED);

	return ret;
}

int qp_mgr::send(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t *)p_send_wqe->wr_id;

	qp_logfunc("VERBS send, unsignaled_count: %d", m_n_unsignaled_count);
	bool request_comp = is_completion_need();

#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_POST_SEND_START;
#endif

#ifdef RDTSC_MEASURE_TX_VERBS_POST_SEND
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_TX_VERBS_POST_SEND]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND

	if (send_to_wire(p_send_wqe, attr, request_comp)) {
#ifdef VMA_TIME_MEASURE
		INC_ERR_TX_COUNT;
#endif
		return -1;
	}

#ifdef RDTSC_MEASURE_TX_VERBS_POST_SEND
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_TX_VERBS_POST_SEND]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND

#ifdef RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND

#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_POST_SEND_END;
#endif
	// Link this new mem_buf_desc to the previous one sent
	p_mem_buf_desc->p_next_desc = m_p_last_tx_mem_buf_desc;

	if (request_comp) {
		int ret;

		set_unsignaled_count();
		m_p_last_tx_mem_buf_desc = NULL;

		if (m_p_ahc_head) { // need to destroy ah
			//save the orig owner
			qp_logdbg("mark with signal!");
			m_p_ahc_tail->m_next_owner = p_mem_buf_desc->p_desc_owner;
			p_mem_buf_desc->p_desc_owner = m_p_ahc_head;
			m_p_ahc_head = m_p_ahc_tail = NULL;
		}

		// Poll the Tx CQ
		uint64_t dummy_poll_sn = 0;
		ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&dummy_poll_sn);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0) {
			qp_logerr("error from cq_mgr_tx->process_next_element (ret=%d %m)", ret);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		qp_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
	} else {
		m_n_unsignaled_count--;
		m_p_last_tx_mem_buf_desc = p_mem_buf_desc;
	}

	return 0;
}

void qp_mgr_eth::modify_qp_to_ready_state()
{
	qp_logdbg("");
	int ret = 0;
	int qp_state = priv_ibv_query_qp_state(m_qp);
	if (qp_state !=  IBV_QPS_INIT) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if ((ret = priv_ibv_modify_qp_from_err_to_init_raw(m_qp, m_port_num)) != 0) {
			qp_logpanic("failed to modify QP from %d to RTS state (ret = %d)", qp_state, ret);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if ((ret = priv_ibv_modify_qp_from_init_to_rts(m_qp)) != 0) {
		qp_logpanic("failed to modify QP from INIT to RTS state (ret = %d)", ret);
	}

	modify_qp_ratelimit(m_rate_limit, RL_RATE | RL_BURST_SIZE | RL_PKT_SIZE);
	BULLSEYE_EXCLUDE_BLOCK_END
}

int qp_mgr_eth::prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr)
{
	qp_logdbg("inline: %d", qp_init_attr.cap.max_inline_data);
	int ret = 0;

	qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
	vma_ibv_qp_init_attr_comp_mask(m_p_ib_ctx_handler->get_ibv_pd(), qp_init_attr);
	m_qp = vma_ibv_create_qp(m_p_ib_ctx_handler->get_ibv_pd(), &qp_init_attr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_qp) {
		qp_logerr("ibv_create_qp failed (errno=%d %m)", errno);
		return -1;
	}
	VALGRIND_MAKE_MEM_DEFINED(m_qp, sizeof(ibv_qp));
	if ((ret = priv_ibv_modify_qp_from_err_to_init_raw(m_qp, m_port_num)) != 0) {
		qp_logerr("failed to modify QP from ERR to INIT state (ret = %d)", ret);
		return ret;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	enum ibv_qp_attr_mask attr_mask = IBV_QP_CAP;
	struct ibv_qp_attr tmp_ibv_qp_attr;
	struct ibv_qp_init_attr tmp_ibv_qp_init_attr;
	IF_VERBS_FAILURE(ibv_query_qp(m_qp, &tmp_ibv_qp_attr, attr_mask,
			 &tmp_ibv_qp_init_attr)) {
			qp_logerr("ibv_query_qp failed (errno=%d %m)", errno);
			return -1;
	} ENDIF_VERBS_FAILURE;
	uint32_t tx_max_inline = safe_mce_sys().tx_max_inline;
	m_max_inline_data = min(tmp_ibv_qp_attr.cap.max_inline_data, tx_max_inline);
	qp_logdbg("requested max inline = %d QP, actual max inline = %d, "
		"VMA max inline set to %d, max_send_wr=%d, max_recv_wr=%d, "
		"max_recv_sge=%d, max_send_sge=%d",
		tx_max_inline, tmp_ibv_qp_init_attr.cap.max_inline_data,
		m_max_inline_data, tmp_ibv_qp_attr.cap.max_send_wr,
		tmp_ibv_qp_attr.cap.max_recv_wr, tmp_ibv_qp_attr.cap.max_recv_sge,
		tmp_ibv_qp_attr.cap.max_send_sge);

	return 0;
}

void qp_mgr_ib::modify_qp_to_ready_state()
{
	qp_logdbg("");
	int ret = 0;
	int qp_state = priv_ibv_query_qp_state(m_qp);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (qp_state !=  IBV_QPS_INIT) {
		if ((ret = priv_ibv_modify_qp_from_err_to_init_ud(m_qp, m_port_num, m_pkey_index, m_underly_qpn)) != 0) {
			qp_logpanic("failed to modify QP from %d to RTS state (ret = %d)", qp_state, ret);
		}
	}
	if ((ret = priv_ibv_modify_qp_from_init_to_rts(m_qp, m_underly_qpn)) != 0) {
		qp_logpanic("failed to modify QP from INIT to RTS state (ret = %d)", ret);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

int qp_mgr_ib::prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr)
{
	qp_logdbg("");
	int ret = 0;

	qp_init_attr.qp_type = IBV_QPT_UD;
	vma_ibv_qp_init_attr_comp_mask(m_p_ib_ctx_handler->get_ibv_pd(), qp_init_attr);
#ifdef DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN
	if (m_underly_qpn) {
		qp_init_attr.comp_mask |= IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN;
		qp_init_attr.associated_qpn = m_underly_qpn;
		qp_logdbg("create qp using underly qpn = 0x%X", m_underly_qpn);
	}
#endif /* DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN */

	m_qp = vma_ibv_create_qp(m_p_ib_ctx_handler->get_ibv_pd(), &qp_init_attr);
#ifdef DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN
	if (!m_qp && m_underly_qpn) {
		qp_logdbg("ibv_create_qp failed to use underly qpn (errno=%d %m)", errno);

		/* try to use traditional approach */
		qp_init_attr.comp_mask &= ~IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN;
		m_underly_qpn = 0;
		m_qp = vma_ibv_create_qp(m_p_ib_ctx_handler->get_ibv_pd(), &qp_init_attr);
	}
#endif /* DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN */

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_qp) {
		qp_logerr("ibv_create_qp failed (errno=%d %m)", errno);
		return -1;
	}

	if ((ret = priv_ibv_modify_qp_from_err_to_init_ud(m_qp, m_port_num,
							  m_pkey_index,
							  m_underly_qpn)) != 0) {
		VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(
				VLOG_ERROR, VLOG_DEBUG,
				"failed to modify QP from ERR to INIT state (ret = %d) check number of available fds (ulimit -n)",
				ret, errno);
		return ret;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	enum ibv_qp_attr_mask attr_mask = IBV_QP_CAP;
	struct ibv_qp_attr tmp_ibv_qp_attr;
	struct ibv_qp_init_attr tmp_ibv_qp_init_attr;
	IF_VERBS_FAILURE(ibv_query_qp(m_qp, &tmp_ibv_qp_attr, attr_mask,
			 &tmp_ibv_qp_init_attr)) {
			qp_logerr("ibv_query_qp failed (errno=%d %m)", errno);
			return -1;
	} ENDIF_VERBS_FAILURE;
	uint32_t tx_max_inline = safe_mce_sys().tx_max_inline;
	m_max_inline_data = min(tmp_ibv_qp_attr.cap.max_inline_data, tx_max_inline);
	qp_logdbg("requested max inline = %d QP, actual max inline = %d, "
		"VMA max inline set to %d, max_send_wr=%d, max_recv_wr=%d, "
		"max_recv_sge=%d, max_send_sge=%d",
		tx_max_inline, tmp_ibv_qp_init_attr.cap.max_inline_data,
		m_max_inline_data, tmp_ibv_qp_attr.cap.max_send_wr,
		tmp_ibv_qp_attr.cap.max_recv_wr, tmp_ibv_qp_attr.cap.max_recv_sge,
		tmp_ibv_qp_attr.cap.max_send_sge);
	return 0;
}

void qp_mgr_ib::update_pkey_index()
{
	qp_logdbg("");
	VALGRIND_MAKE_MEM_DEFINED(&m_pkey, sizeof(m_pkey));
	if (priv_ibv_find_pkey_index(m_p_ib_ctx_handler->get_ibv_context(), get_port_num(), m_pkey, &m_pkey_index)) {
		qp_logdbg("IB: Can't find correct pkey_index for pkey '%d'", m_pkey);
		m_pkey_index = (uint16_t)-1;
	}
	else {
		qp_logdbg("IB: Found correct pkey_index (%d) for pkey '%d'", m_pkey_index, m_pkey);
	}
#ifdef DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN
	/* m_underly_qpn is introduced to detect if current qp_mgr is able to
	 * use associated qp.
	 * It is set to non zero value if OFED supports such possibility only but final
	 * decision can be made just after attempt to create qp. The value of
	 * m_underly_qpn is reverted to zero if function to qp creation returns
	 * failure.
	 * So zero value for this field means no such capability.
	 * Note: mlx4 does not support this capability. Disable it explicitly because dynamic check
	 * using ibv_create_qp does not help
	 */
	if (strncmp(m_p_ib_ctx_handler->get_ibname(), "mlx4", 4)) {
		m_underly_qpn = m_p_ring->get_qpn();
	}
	qp_logdbg("IB: Use qpn = 0x%X for device: %s", m_underly_qpn, m_p_ib_ctx_handler->get_ibname());
#endif /* DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN */
}

uint32_t qp_mgr::is_ratelimit_change(struct vma_rate_limit_t &rate_limit)
{
	uint32_t rl_changes = 0;

	if (m_rate_limit.rate != rate_limit.rate) {
		rl_changes |= RL_RATE;
	}
	if (m_rate_limit.max_burst_sz != rate_limit.max_burst_sz) {
		rl_changes |= RL_BURST_SIZE;
	}
	if (m_rate_limit.typical_pkt_sz != rate_limit.typical_pkt_sz) {
		rl_changes |= RL_PKT_SIZE;
	}

	return rl_changes;
}

bool qp_mgr::is_ratelimit_supported(vma_ibv_device_attr *attr, struct vma_rate_limit_t &rate_limit)
{
#ifdef DEFINED_IBV_EXP_QP_RATE_LIMIT
	if (!(attr->comp_mask & IBV_EXP_DEVICE_ATTR_PACKET_PACING_CAPS))
		return false;

	ibv_exp_packet_pacing_caps pp_caps = attr->packet_pacing_caps;

	/* for any rate limit settings the rate must be between the supported min and max values */
	if (rate_limit.rate < pp_caps.qp_rate_limit_min || pp_caps.qp_rate_limit_max < rate_limit.rate) {
		return false;
	}

	uint32_t rl_changes = is_ratelimit_change(rate_limit);

	/* burst support capability is required to handle any burst/packet size change */
	if (rl_changes & (RL_BURST_SIZE | RL_PKT_SIZE)) {
#ifdef DEFINED_IBV_EXP_QP_SUPPORT_BURST
		if (!(pp_caps.cap_flags & IBV_EXP_QP_SUPPORT_BURST)) {
			return false;
		}
#else
		return false;
#endif
	}

	return true;
#else
	NOT_IN_USE(attr);
	NOT_IN_USE(rate_limit);
	return false;
#endif
}

int qp_mgr::modify_qp_ratelimit(struct vma_rate_limit_t &rate_limit, uint32_t rl_changes)
{
	int ret;

	ret = priv_ibv_modify_qp_ratelimit(m_qp, rate_limit, rl_changes);
	if (ret) {
		qp_logdbg("failed to modify qp ratelimit ret %d (errno=%d %m)", ret, errno);
		return -1;
	}

	m_rate_limit = rate_limit;
	return 0;
}
