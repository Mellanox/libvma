/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
#include "util/valgrind.h"

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

#define MAX_UPSTREAM_CQ_MSHV_SIZE 8192

qp_mgr::qp_mgr(struct qp_mgr_desc *desc, const uint32_t tx_num_wr):
	m_qp(NULL)
	,m_rq_wqe_idx_to_wrid(NULL)
	,m_p_ring((ring_simple*)desc->ring)
	,m_port_num((uint8_t)desc->slave->port_num)
	,m_p_ib_ctx_handler((ib_ctx_handler*)desc->slave->p_ib_ctx)
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
	m_max_inline_data = 0;
	m_ibv_rx_sg_array = new ibv_sge[m_n_sysvar_rx_num_wr_to_post_recv];
	m_ibv_rx_wr_array = new ibv_recv_wr[m_n_sysvar_rx_num_wr_to_post_recv];

	set_unsignaled_count();
	memset(&m_rate_limit, 0, sizeof(struct vma_rate_limit_t));

	qp_logfunc("");
}

qp_mgr::~qp_mgr()
{
	qp_logfunc("");

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

	qp_logdbg("Rx buffer poll: %ld free global buffers available", g_buffer_pool_rx->get_free_count());
	qp_logdbg("delete done");
}

cq_mgr* qp_mgr::handle_cq_initialization(uint32_t *num_wr, struct ibv_comp_channel* comp_event_channel, bool is_rx)
{
	qp_logfunc("");
	cq_mgr* cq = NULL;

	try {
		cq = new cq_mgr(m_p_ring, m_p_ib_ctx_handler, *num_wr, comp_event_channel, is_rx);
	} catch (vma_exception& e) {
		// This is a workaround for an issue with cq creation of mlx4 devices on
		// upstream-driver VMs over Windows Hypervisor.
		if (safe_mce_sys().hypervisor == mce_sys_var::HYPER_MSHV && m_p_ib_ctx_handler->is_mlx4() &&
				*num_wr > MAX_UPSTREAM_CQ_MSHV_SIZE) {
			qp_logdbg("cq creation failed with cq_size of %d. retrying with size of %d", *num_wr, MAX_UPSTREAM_CQ_MSHV_SIZE);
			*num_wr = MAX_UPSTREAM_CQ_MSHV_SIZE;
			try {
				cq = new cq_mgr(m_p_ring, m_p_ib_ctx_handler, *num_wr, comp_event_channel, is_rx);
			} catch (vma_exception&) {
			}
		}

		if (!cq) {
			qp_logerr("%s", e.message);
		}
	}

	return cq;
}

cq_mgr* qp_mgr::init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel)
{
	return handle_cq_initialization(&m_rx_num_wr, p_rx_comp_event_channel, true);
}

cq_mgr* qp_mgr::init_tx_cq_mgr()
{
	return handle_cq_initialization(&m_tx_num_wr, m_p_ring->get_tx_comp_event_channel(), false);
}

int qp_mgr::configure(struct qp_mgr_desc *desc)
{
	qp_logdbg("Creating QP on ibv device '%s' [%p] on port %d",
			m_p_ib_ctx_handler->get_ibname(), m_p_ib_ctx_handler->get_ibv_device(), m_port_num);

	// Check device capabilities for max QP work requests
	m_max_qp_wr = ALIGN_WR_DOWN(VMA_MAX_QP_WR - 1);
	if (m_rx_num_wr > m_max_qp_wr) {
		qp_logwarn("Allocating only %d Rx QP work requests while user "
			   "requested %s=%d for QP on <%p, %d>",
			   m_max_qp_wr, SYS_VAR_RX_NUM_WRE, m_rx_num_wr,
			   m_p_ib_ctx_handler, m_port_num);
		m_rx_num_wr = m_max_qp_wr;
	}

	qp_logdbg("HW Dummy send support for QP = %d", m_hw_dummy_send_support);

	// Create associated Tx & Rx cq_mgrs
	m_p_cq_mgr_tx = init_tx_cq_mgr();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_cq_mgr_tx) {
		qp_logerr("Failed allocating m_p_cq_mgr_tx (errno=%d %m)", errno);
		return -1;
	}
	m_p_cq_mgr_rx = init_rx_cq_mgr(desc->rx_comp_event_channel);
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
	uint32_t rx_num_sge = (m_p_ring->is_socketxtreme() ? 1 : MCE_DEFAULT_RX_NUM_SGE);
	uint32_t tx_num_sge = MCE_DEFAULT_TX_NUM_SGE;

	qp_init_attr.cap.max_send_wr = m_tx_num_wr;
	qp_init_attr.cap.max_recv_wr = m_rx_num_wr;
	qp_init_attr.cap.max_inline_data = tx_max_inline;
	qp_init_attr.cap.max_send_sge = tx_num_sge;
	qp_init_attr.cap.max_recv_sge = rx_num_sge;
	qp_init_attr.recv_cq = m_p_cq_mgr_rx->get_ibv_cq_hndl();
	qp_init_attr.send_cq = m_p_cq_mgr_tx->get_ibv_cq_hndl();
	qp_init_attr.sq_sig_all = 0;

	qp_logdbg("Calling ibv_create_qp. qp_init_attr.cap: max_send_wr=%d, max_recv_wr=%d, "
		      "max_inline_data=%d, max_send_sge=%d, max_recv_sge=%d\n",
	          qp_init_attr.cap.max_send_wr, qp_init_attr.cap.max_recv_wr,
			  qp_init_attr.cap.max_inline_data, qp_init_attr.cap.max_send_sge,
			  qp_init_attr.cap.max_recv_sge);

	// Create the QP
	if (prepare_ibv_qp(qp_init_attr)) {
		return -1;
	}

	qp_logdbg("Created QP (num=%d) with %d tx wre and inline=%d and %d rx "
		"wre and %d sge", m_qp->qp_num, m_tx_num_wr, m_max_inline_data,
		m_rx_num_wr, rx_num_sge);

#if defined(DEFINED_ROCE_LAG)
	if (desc->slave && desc->slave->lag_tx_port_affinity > 0) {
			const slave_data_t * p_slave = desc->slave;
			struct mlx5dv_context attr_out;

			memset(&attr_out, 0, sizeof(attr_out));
			attr_out.comp_mask |= MLX5DV_CONTEXT_MASK_NUM_LAG_PORTS;
			if (!mlx5dv_query_device(p_slave->p_ib_ctx->get_ibv_context(), &attr_out)) {
				qp_logdbg("QP ROCE LAG port: %d of %d", p_slave->lag_tx_port_affinity, attr_out.num_lag_ports);

				if (!mlx5dv_modify_qp_lag_port(m_qp, p_slave->lag_tx_port_affinity)) {
					uint8_t current_port_num = 0;
					uint8_t active_port_num = 0;

					if (!mlx5dv_query_qp_lag_port(m_qp, &current_port_num, &active_port_num)) {
						qp_logdbg("QP ROCE LAG port affinity: %d => %d", current_port_num, active_port_num);
					}
				}
			}
		}
#endif /* DEFINED_ROCE_LAG */

	// All buffers will be allocated from this qp_mgr buffer pool so we can already set the Rx & Tx lkeys
	for (uint32_t wr_idx = 0; wr_idx < m_n_sysvar_rx_num_wr_to_post_recv; wr_idx++) {
		m_ibv_rx_wr_array[wr_idx].sg_list = &m_ibv_rx_sg_array[wr_idx];
		m_ibv_rx_wr_array[wr_idx].num_sge = 1;
		m_ibv_rx_wr_array[wr_idx].next = (wr_idx < (m_n_sysvar_rx_num_wr_to_post_recv - 1) ?
					&m_ibv_rx_wr_array[wr_idx+1] : NULL); // pre-define the linked list
	}

	m_curr_rx_wr = 0;

	if (m_p_cq_mgr_tx) {
		m_p_cq_mgr_tx->add_qp_tx(this);
	}

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
				m_p_ring->mem_buf_desc_return_to_owner_rx(p_mem_buf_desc);
			}
			else {
				g_buffer_pool_rx->put_buffers_thread_safe(p_mem_buf_desc);
			}
		}
	}
	// Wait for all FLUSHed WQE on Rx CQ
	qp_logdbg("draining rx cq_mgr %p (last_posted_rx_wr_id = %lu)", m_p_cq_mgr_rx, m_last_posted_rx_wr_id);
	uintptr_t last_polled_rx_wr_id = 0;
	while (m_p_cq_mgr_rx && last_polled_rx_wr_id != m_last_posted_rx_wr_id &&
			errno != EIO && !m_p_ib_ctx_handler->is_removed() &&
			!is_rq_empty()) {

		// Process the FLUSH'ed WQE's
		int ret = m_p_cq_mgr_rx->drain_and_proccess(&last_polled_rx_wr_id);
		qp_logdbg("draining completed on rx cq_mgr (%d wce) last_polled_rx_wr_id = %lu", ret, last_polled_rx_wr_id);

		total_ret += ret;

		if (!ret) {
			// Query context for ib_verbs events (especially for IBV_EVENT_DEVICE_FATAL)
			g_p_event_handler_manager->query_for_ibverbs_event(m_p_ib_ctx_handler->get_ibv_context()->async_fd);
		}

		// Add short delay (500 usec) to allow for WQE's to be flushed to CQ every poll cycle
		const struct timespec short_sleep = {0, 500000}; // 500 usec
		nanosleep(&short_sleep, NULL);
	}
	m_last_posted_rx_wr_id = 0; // Clear the posted WR_ID flag, we just clear the entire RQ
	qp_logdbg("draining completed with a total of %d wce's on rx cq_mgr", total_ret);
}

void qp_mgr::release_tx_buffers()
{
	int ret = 0;
	uint64_t poll_sn = 0;
	qp_logdbg("draining tx cq_mgr %p", m_p_cq_mgr_tx);
	while (m_p_cq_mgr_tx && m_qp &&
			((ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn)) > 0) &&
			(errno != EIO && !m_p_ib_ctx_handler->is_removed())) {
		qp_logdbg("draining completed on tx cq_mgr (%d wce)", ret);
	}
}

void qp_mgr::trigger_completion_for_all_sent_packets()
{
	ibv_send_wr send_wr;
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

		/* need to send at least eth+ip, since libmlx5 will drop just eth header */
		ethhdr* p_buffer_ethhdr = (ethhdr *)p_mem_buf_desc->p_buffer;
		memset(p_buffer_ethhdr, 0, sizeof(*p_buffer_ethhdr));
		p_buffer_ethhdr->h_proto = htons(ETH_P_IP);
		iphdr* p_buffer_iphdr = (iphdr *)(p_mem_buf_desc->p_buffer + sizeof(*p_buffer_ethhdr));
		memset(p_buffer_iphdr, 0, sizeof(*p_buffer_iphdr));
		sge[0].length = sizeof(ethhdr) + sizeof(iphdr);
		sge[0].addr = (uintptr_t)(p_mem_buf_desc->p_buffer);
		sge[0].lkey = m_p_ring->m_tx_lkey;

		memset(&send_wr, 0, sizeof(send_wr));
		send_wr.wr_id = (uintptr_t)p_mem_buf_desc;
		send_wr.wr.ud.ah = nullptr;
		send_wr.sg_list = sge;
		send_wr.num_sge = 1;
		send_wr.next = NULL;
		vma_send_wr_opcode(send_wr) = IBV_WR_SEND;
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
	}
}

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

	if (m_curr_rx_wr == m_n_sysvar_rx_num_wr_to_post_recv - 1) {

		m_last_posted_rx_wr_id = (uintptr_t)p_mem_buf_desc;

		m_p_prev_rx_desc_pushed = NULL;
		p_mem_buf_desc->p_prev_desc = NULL;

		m_curr_rx_wr = 0;
		struct ibv_recv_wr *bad_wr = NULL;
		IF_VERBS_FAILURE(ibv_post_recv(m_qp, &m_ibv_rx_wr_array[0], &bad_wr)) {
			uint32_t n_pos_bad_rx_wr = ((uint8_t*)bad_wr - (uint8_t*)m_ibv_rx_wr_array) / sizeof(struct ibv_recv_wr);
			qp_logerr("failed posting list (errno=%d %m)", errno);
			qp_logerr("bad_wr is %d in submitted list (bad_wr=%p, m_ibv_rx_wr_array=%p, size=%zu)", n_pos_bad_rx_wr, bad_wr, m_ibv_rx_wr_array, sizeof(struct ibv_recv_wr));
			qp_logerr("bad_wr info: wr_id=%#lx, next=%p, addr=%#lx, length=%d, lkey=%#x", bad_wr[0].wr_id, bad_wr[0].next, bad_wr[0].sg_list[0].addr, bad_wr[0].sg_list[0].length, bad_wr[0].sg_list[0].lkey);
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

inline int qp_mgr::send_to_wire(ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr, bool request_comp)
{
	NOT_IN_USE(attr);
	int ret = 0;
	ibv_send_wr *bad_wr = NULL;

	if (request_comp) {
		vma_send_wr_send_flags(*p_send_wqe) = (ibv_send_flags)(vma_send_wr_send_flags(*p_send_wqe) | IBV_SEND_SIGNALED);
	}

	IF_VERBS_FAILURE(ibv_post_send(m_qp, p_send_wqe, &bad_wr)) {
		qp_logerr("failed post_send%s (errno=%d %m)\n", ((vma_send_wr_send_flags(*p_send_wqe) & IBV_SEND_INLINE)?"(+inline)":""), errno);
		if (bad_wr) {
			qp_logerr("bad_wr info: wr_id=%#lx, send_flags=%#lx, addr=%#lx, length=%d, lkey=%#x, max_inline_data=%d",
			bad_wr->wr_id, (unsigned long)vma_send_wr_send_flags(*bad_wr), bad_wr->sg_list[0].addr, bad_wr->sg_list[0].length, bad_wr->sg_list[0].lkey, get_max_inline_data());
		}
		ret = -1;
	} ENDIF_VERBS_FAILURE;

	// Clear the SINGAL request
	vma_send_wr_send_flags(*p_send_wqe) = (ibv_send_flags)(vma_send_wr_send_flags(*p_send_wqe) & ~IBV_SEND_SIGNALED);

	return ret;
}

int qp_mgr::send(ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
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

	BULLSEYE_EXCLUDE_BLOCK_END
}

int qp_mgr_eth::prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr)
{
	qp_logdbg("");
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
