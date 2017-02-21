/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#include "qp_mgr.h"
#include "vma/util/bullseye.h"
#include "vma/util/utils.h"
#include "vma/iomux/io_mux_call.h"
#include "buffer_pool.h"
#include "cq_mgr.h"
#include "vma/util/instrumentation.h"
#include "ring_simple.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"qpm"

#define qp_logpanic 		__log_info_panic
#define qp_logerr		__log_info_err
#define qp_logwarn		__log_info_warn
#define qp_loginfo		__log_info_info
#define qp_logdbg		__log_info_dbg
#define qp_logfunc		__log_info_func
#define qp_logfuncall		__log_info_funcall


//#define ALIGN_WR_UP(_num_wr_) 		(max(32, ((_num_wr_ + 0xf) & ~(0xf))))
#define ALIGN_WR_DOWN(_num_wr_) 		(max(32, ((_num_wr_      ) & ~(0xf))))

#define FICTIVE_REMOTE_QPN	0x48
#define FICTIVE_REMOTE_QKEY	0x01234567
#define FICTIVE_AH_SL		5
#define FICTIVE_AH_DLID		0x3

qp_mgr::qp_mgr(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num, const uint32_t tx_num_wr):
	m_qp(NULL), m_p_ring((ring_simple*)p_ring), m_port_num((uint8_t)port_num), m_p_ib_ctx_handler((ib_ctx_handler*)p_context),
	m_p_ahc_head(NULL), m_p_ahc_tail(NULL), m_max_inline_data(0), m_max_qp_wr(0), m_p_cq_mgr_rx(NULL), m_p_cq_mgr_tx(NULL),
	m_rx_num_wr(safe_mce_sys().rx_num_wr), m_tx_num_wr(tx_num_wr), m_rx_num_wr_to_post_recv(safe_mce_sys().rx_num_wr_to_post_recv), 
	m_curr_rx_wr(0), m_last_posted_rx_wr_id(0), m_n_unsignaled_count(0), m_n_tx_count(0), m_p_last_tx_mem_buf_desc(NULL), m_p_prev_rx_desc_pushed(NULL),
	m_n_ip_id_base(0), m_n_ip_id_offset(0)
{
	m_ibv_rx_sg_array = new ibv_sge[m_rx_num_wr_to_post_recv];
	m_ibv_rx_wr_array = new ibv_recv_wr[m_rx_num_wr_to_post_recv];
	m_rq_wqe_counter = 0;
	m_sq_wqe_counter = 0;

	m_rq_wqe_idx_to_wrid = (uint64_t*)mmap(NULL, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid),
		PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (m_rq_wqe_idx_to_wrid == MAP_FAILED) {
		qp_logerr("Failed allocating m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
	}
	m_sq_wqe_idx_to_wrid = (uint64_t*)mmap(NULL, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_wrid),
		PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (m_sq_wqe_idx_to_wrid == MAP_FAILED) {
		qp_logerr("Failed allocating m_sq_wqe_idx_to_wrid (errno=%d %m)", errno);
	}
}

qp_mgr::~qp_mgr()
{
	qp_logfunc("");

	// Don't assume anything
	// release_tx/rx_buffers() - poll and process the CQ's
	release_tx_buffers();
	release_rx_buffers();

	qp_logdbg("calling ibv_destroy_qp(qp=%p)", m_qp);
	IF_VERBS_FAILURE(ibv_destroy_qp(m_qp)) {
		qp_logdbg("QP destroy failure (errno = %d %m)", -errno);
	} ENDIF_VERBS_FAILURE;
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

	munmap(m_rq_wqe_idx_to_wrid, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid));
	munmap(m_sq_wqe_idx_to_wrid, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_wrid));

	qp_logdbg("Rx buffer poll: %d free global buffers available", g_buffer_pool_rx->get_free_count());
	qp_logdbg("delete done");
}

int qp_mgr::configure(struct ibv_comp_channel* p_rx_comp_event_channel)
{
	qp_logdbg("Creating QP of transport type '%s' on ibv device '%s' [%p] on port %d",
			priv_vma_transport_type_str(m_p_ring->get_transport_type()),
			m_p_ib_ctx_handler->get_ibv_device()->name, m_p_ib_ctx_handler->get_ibv_device(), m_port_num);

	// Check device capabilities for max QP work requests
	vma_ibv_device_attr& r_ibv_dev_attr = m_p_ib_ctx_handler->get_ibv_device_attr();
	m_max_qp_wr = ALIGN_WR_DOWN(r_ibv_dev_attr.max_qp_wr - 1);;
	if (m_rx_num_wr > m_max_qp_wr) {
		qp_logwarn("Allocating only %d Rx QP work requests while user requested %s=%d for QP on <%p, %d>",
			   m_max_qp_wr, SYS_VAR_RX_NUM_WRE, m_rx_num_wr, m_p_ib_ctx_handler, m_port_num);
		m_rx_num_wr = m_max_qp_wr;
	}

	// Create associated Tx & Rx cq_mgrs
	m_p_cq_mgr_tx = new cq_mgr(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr, m_p_ring->get_tx_comp_event_channel(), false);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_cq_mgr_tx) {
		qp_logerr("Failed allocating m_p_cq_mgr_tx (errno=%d %m)", errno);
		return -1;
	}

	m_p_cq_mgr_rx = new cq_mgr(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr, p_rx_comp_event_channel, true);
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
	struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	// Check device capabilities for max SG elements
	uint32_t tx_max_inline = safe_mce_sys().tx_max_inline;;
	uint32_t rx_num_sge = 1; /* MCE_DEFAULT_RX_NUM_SGE; */

	qp_init_attr.cap.max_send_wr = m_tx_num_wr;
	qp_init_attr.cap.max_recv_wr = m_rx_num_wr;
	qp_init_attr.cap.max_inline_data = tx_max_inline;
	qp_init_attr.cap.max_recv_sge = rx_num_sge;
	qp_init_attr.recv_cq = m_p_cq_mgr_rx->get_ibv_cq_hndl();
	qp_init_attr.send_cq = m_p_cq_mgr_tx->get_ibv_cq_hndl();
	qp_init_attr.sq_sig_all = 0;

	// Create the QP
	if (prepare_ibv_qp(qp_init_attr)) {
		return -1;
	}

	int attr_mask = IBV_QP_CAP;
	struct ibv_qp_attr tmp_ibv_qp_attr;
	struct ibv_qp_init_attr tmp_ibv_qp_init_attr;
	IF_VERBS_FAILURE(ibv_query_qp(m_qp, &tmp_ibv_qp_attr, (enum ibv_qp_attr_mask)attr_mask, &tmp_ibv_qp_init_attr)) {
		qp_logerr("ibv_query_qp failed (errno=%d %m)", errno);
		return -1;
	} ENDIF_VERBS_FAILURE;

	struct verbs_qp *vqp = (struct verbs_qp *)m_qp;
	m_mlx5_hw_qp = (struct mlx5_qp*)container_of(vqp, struct mlx5_qp, verbs_qp);

	m_qp_num = m_mlx5_hw_qp->ctrl_seg.qp_num;
	m_mlx5_sq_wqes = (volatile struct mlx5_wqe64 (*)[])(uintptr_t)m_mlx5_hw_qp->gen_data.sqstart;
	m_sq_db = &m_mlx5_hw_qp->gen_data.db[MLX5_SND_DBR];
	m_sq_bf_reg = m_mlx5_hw_qp->gen_data.bf->reg;
	m_sq_bf_offset = m_mlx5_hw_qp->gen_data.bf->offset;
	m_sq_bf_buf_size = m_mlx5_hw_qp->gen_data.bf->buf_size;
	mlx5_init_sq();

	m_max_inline_data = min(tmp_ibv_qp_init_attr.cap.max_inline_data, tx_max_inline);
	qp_logdbg("requested max inline = %d QP, actual max inline = %d, VMA max inline set to %d, max_send_wr=%d, max_recv_wr=%d, max_recv_sge=%d",
			tx_max_inline, tmp_ibv_qp_init_attr.cap.max_inline_data, m_max_inline_data, qp_init_attr.cap.max_send_wr, qp_init_attr.cap.max_recv_wr, qp_init_attr.cap.max_recv_sge);

	// All buffers will be allocated from this qp_mgr buffer pool so we can already set the Rx & Tx lkeys
	for (uint32_t wr_idx = 0; wr_idx < m_rx_num_wr_to_post_recv; wr_idx++) {
		m_ibv_rx_wr_array[wr_idx].sg_list = &m_ibv_rx_sg_array[wr_idx];
		m_ibv_rx_wr_array[wr_idx].num_sge = 1;
		m_ibv_rx_wr_array[wr_idx].next = &m_ibv_rx_wr_array[wr_idx+1]; // pre-define the linked list
	}
	m_ibv_rx_wr_array[m_rx_num_wr_to_post_recv-1].next = NULL; // end linked list

	m_curr_rx_wr = 0;

	m_p_ahc_head = NULL;
	m_p_ahc_tail = NULL;
	
	if (m_p_cq_mgr_tx) {
		m_p_cq_mgr_tx->add_qp_tx(this);
	}

	qp_logdbg("Created QP (num=%x) with %d tx wre and inline=%d and %d rx wre and %d sge", m_qp->qp_num, m_tx_num_wr, m_max_inline_data, m_rx_num_wr, rx_num_sge);

	return 0;
}

void qp_mgr::up()
{
	// Add buffers
	qp_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_qp));
	release_rx_buffers(); // We might have old flushed cqe's in our CQ still from previous HA event
	release_tx_buffers();

	/* clean any link to completions with error we might have */
	m_n_unsignaled_count = 0;
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
	if (!m_p_ib_ctx_handler->is_removed()) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (priv_ibv_modify_qp_to_err(m_qp)) {
			qp_logdbg("ibv_modify_qp failure (errno = %d %m)", errno);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}
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
	qp_logdbg("draining rx cq_mgr %p (last_posted_rx_wr_id = %x)", m_p_cq_mgr_rx, m_last_posted_rx_wr_id);
	uintptr_t last_polled_rx_wr_id = 0;
	while (m_p_cq_mgr_rx && last_polled_rx_wr_id != m_last_posted_rx_wr_id) {

		// Process the FLUSH'ed WQE's
		int ret = m_p_cq_mgr_rx->drain_and_proccess(&last_polled_rx_wr_id);
		qp_logdbg("draining completed on rx cq_mgr (%d wce)", ret);
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

void qp_mgr::set_signal_in_next_send_wqe()
{
	volatile struct mlx5_wqe64 *wqe = &(*m_mlx5_sq_wqes)[m_sq_wqe_counter & (m_tx_num_wr - 1)];
	wqe->ctrl.data[2] = htonl(8);
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
			ah_attr.src_path_bits	= 	0;
			ah_attr.static_rate	= 	0;
			ah_attr.is_global	= 	0;
			ah_attr.port_num	= 	m_port_num; // Do we need it?

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
		vma_send_wr_send_flags(send_wr) = (vma_ibv_send_flags)(VMA_IBV_SEND_SIGNALED /*| VMA_IBV_SEND_INLINE*/); //todo inline only if inline is on
		qp_logdbg("IBV_SEND_SIGNALED");

		// Close the Tx unsignaled send list
		m_n_unsignaled_count = 0;
		m_p_last_tx_mem_buf_desc = NULL;

		if (!m_p_ring->m_tx_num_wr_free) {
			qp_logdbg("failed to trigger completion for all packets due to no available wr");
			return;
		}
		m_p_ring->m_tx_num_wr_free--;
		set_signal_in_next_send_wqe();
		mlx5_send(&send_wr);

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

int qp_mgr::post_recv(mem_buf_desc_t* p_mem_buf_desc)
{
	qp_logfuncall("");
	// Called from cq_mgr context under cq_mgr::LOCK!

	mem_buf_desc_t *next;
	while (p_mem_buf_desc) {
		next = p_mem_buf_desc->p_next_desc;
		p_mem_buf_desc->p_next_desc = NULL;

		if (safe_mce_sys().rx_prefetch_bytes_before_poll) {
			if (m_p_prev_rx_desc_pushed)
				m_p_prev_rx_desc_pushed->p_prev_desc = p_mem_buf_desc;
			m_p_prev_rx_desc_pushed = p_mem_buf_desc;
		}

		m_ibv_rx_wr_array[m_curr_rx_wr].wr_id  = (uintptr_t)p_mem_buf_desc;
		m_ibv_rx_sg_array[m_curr_rx_wr].addr   = (uintptr_t)p_mem_buf_desc->p_buffer;
		m_ibv_rx_sg_array[m_curr_rx_wr].length = p_mem_buf_desc->sz_buffer;
		m_ibv_rx_sg_array[m_curr_rx_wr].lkey   = p_mem_buf_desc->lkey;

		uint64_t index = m_rq_wqe_counter & (m_rx_num_wr - 1);

		m_rq_wqe_idx_to_wrid[index] = (uintptr_t)p_mem_buf_desc;
		m_rq_wqe_counter++;

		if (m_curr_rx_wr == m_rx_num_wr_to_post_recv-1) {

			m_last_posted_rx_wr_id = (uintptr_t)p_mem_buf_desc;

			m_p_prev_rx_desc_pushed = NULL;
			p_mem_buf_desc->p_prev_desc = NULL;

			m_curr_rx_wr = 0;
			struct ibv_recv_wr *bad_wr = NULL;
			IF_VERBS_FAILURE(ibv_post_recv(m_qp, &m_ibv_rx_wr_array[0], &bad_wr)) {
				uint32_t n_pos_bad_rx_wr = ((uint8_t*)bad_wr - (uint8_t*)m_ibv_rx_wr_array) / sizeof(struct ibv_recv_wr);
				qp_logerr("failed posting list (errno=%d %m)", errno);
				qp_logdbg("bad_wr is %d in submitted list (bad_wr=%p, m_ibv_rx_wr_array=%p, size=%d)", n_pos_bad_rx_wr, bad_wr, m_ibv_rx_wr_array, sizeof(struct ibv_recv_wr));
				qp_logdbg("bad_wr info: wr_id=%#x, next=%p, addr=%#x, length=%d, lkey=%#x", bad_wr[0].wr_id, bad_wr[0].next, bad_wr[0].sg_list[0].addr, bad_wr[0].sg_list[0].length, bad_wr[0].sg_list[0].lkey);
				qp_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_qp));

				// Fix broken linked list of rx_wr
				if (n_pos_bad_rx_wr != (m_rx_num_wr_to_post_recv-1)) {
					m_ibv_rx_wr_array[n_pos_bad_rx_wr].next = &m_ibv_rx_wr_array[n_pos_bad_rx_wr+1];
				}
				throw;
			} ENDIF_VERBS_FAILURE;
			qp_logfunc("Successful ibv_post_recv");
		}
		else {
			m_curr_rx_wr++;
		}


		p_mem_buf_desc = next;
	}

	return 0;
}

static inline void mlx5_bf_copy(volatile uintptr_t *dst, volatile uintptr_t *src)
{
	COPY_64B_NT(dst, src);
}

void qp_mgr::mlx5_send(vma_ibv_send_wr *p_send_wqe)
{
	uintptr_t addr = 0;
	uint32_t length = 0;
	uint32_t lkey = 0;

	addr = p_send_wqe->sg_list[0].addr;
	length = p_send_wqe->sg_list[0].length;
	lkey = p_send_wqe->sg_list[0].lkey;

	/* Copy the first bytes into the inline header */
	memcpy((void *)m_sq_hot_wqe->eseg.inline_hdr_start,
	       (void *)addr,
	       MLX5_ETH_INLINE_HEADER_SIZE);

	addr += MLX5_ETH_INLINE_HEADER_SIZE;
	length -= MLX5_ETH_INLINE_HEADER_SIZE;

	m_sq_hot_wqe->dseg.byte_count = htonl(length);
	m_sq_hot_wqe->dseg.lkey = htonl(lkey);
	m_sq_hot_wqe->dseg.addr = htonll(addr);

	++m_sq_wqe_counter;

	/*
	 * Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();
	*m_sq_db = htonl(m_sq_wqe_counter);

	/* This wc_wmb ensures ordering between DB record and BF copy */
	wc_wmb();

	/*
	 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
	 * implementations may use move-string-buffer assembler instructions,
	 * which do not guarantee order of copying.
	 */
	mlx5_bf_copy((volatile uintptr_t *)((uintptr_t)m_sq_bf_reg + m_sq_bf_offset),
		(volatile uintptr_t *)m_sq_hot_wqe);

	m_sq_bf_offset ^= m_sq_bf_buf_size;

	m_sq_wqe_idx_to_wrid[m_sq_hot_wqe_index] = (uintptr_t)p_send_wqe->wr_id;

	/*Set the next WQE and index*/
	m_sq_hot_wqe = &(*m_mlx5_sq_wqes)[m_sq_wqe_counter & (m_tx_num_wr - 1)];
	/* Write only data[0] which is the single element which changes.
	 * Other fields are already initialised in mlx5_init_sq. */
	m_sq_hot_wqe->ctrl.data[0] = htonl((m_sq_wqe_counter << 8) | MLX5_OPCODE_SEND);
	m_sq_hot_wqe_index = m_sq_wqe_counter & (m_tx_num_wr - 1);
}

void qp_mgr::mlx5_init_sq()
{
	unsigned int i;
	unsigned int comp = NUM_TX_POST_SEND_NOTIFY;

	for (i = 0; (i != m_tx_num_wr); ++i) {
		volatile struct mlx5_wqe64 *wqe = &(*m_mlx5_sq_wqes)[i];

		memset((void *)(uintptr_t)wqe, 0, sizeof(struct mlx5_wqe64));
		wqe->eseg.inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);
		wqe->eseg.cs_flags = MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
		wqe->ctrl.data[1] = htonl((m_qp_num << 8) | 4);
		//wqe->dseg.lkey = (m_p_ring->get_lkey());
		/* Store the completion request in the WQE. */
		if (--comp == 0) {
			wqe->ctrl.data[2] = htonl(8);
			comp = NUM_TX_POST_SEND_NOTIFY;
		}
		else
			wqe->ctrl.data[2] = 0;
	}
	m_sq_hot_wqe = &(*m_mlx5_sq_wqes)[0];
	m_sq_hot_wqe->ctrl.data[0] = htonl(MLX5_OPCODE_SEND);
	m_sq_hot_wqe_index = 0;
	qp_logdbg("%p: allocated and configured %u WRs", this, m_tx_num_wr);
}

int qp_mgr::send(vma_ibv_send_wr* p_send_wqe)
{
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t *)p_send_wqe->wr_id;
	bool is_signaled;
	int ret;

	qp_logfunc("");

	is_signaled = ++m_n_unsignaled_count >= NUM_TX_POST_SEND_NOTIFY;

	// Link this new mem_buf_desc to the previous one sent
	p_mem_buf_desc->p_next_desc = m_p_last_tx_mem_buf_desc;

	if (is_signaled) {
		m_n_unsignaled_count = 0;
		m_p_last_tx_mem_buf_desc = NULL;
		qp_logfunc("IBV_SEND_SIGNALED");

		if (m_p_ahc_head) { // need to destroy ah
			//save the orig owner
			qp_logdbg("mark with signal!");
			m_p_ahc_tail->m_next_owner = p_mem_buf_desc->p_desc_owner;
			p_mem_buf_desc->p_desc_owner = m_p_ahc_head;
			m_p_ahc_head = m_p_ahc_tail = NULL;
		}
	}
	else {
		m_p_last_tx_mem_buf_desc = p_mem_buf_desc;
	}
	++m_n_tx_count;

#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_POST_SEND_START;
#endif

#ifdef RDTSC_MEASURE_TX_VERBS_POST_SEND
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_TX_VERBS_POST_SEND]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
	mlx5_send(p_send_wqe);
#ifdef RDTSC_MEASURE_TX_VERBS_POST_SEND
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_TX_VERBS_POST_SEND]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND

#ifdef RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND

#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_POST_SEND_END;
#endif

	if (is_signaled) {

		// Clear the SINGAL request
		//vma_send_wr_send_flags(*p_send_wqe) = (vma_ibv_send_flags)(vma_send_wr_send_flags(*p_send_wqe) & ~VMA_IBV_SEND_SIGNALED);

		// Poll the Tx CQ
		uint64_t dummy_poll_sn = 0;
		m_n_tx_count = 0;
		ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&dummy_poll_sn);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0) {
			qp_logerr("error from cq_mgr_tx->process_next_element (ret=%d %m)", ret);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		qp_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
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

int qp_mgr_eth::prepare_ibv_qp(struct ibv_qp_init_attr& qp_init_attr)
{
	qp_logdbg("");
	int ret = 0;
	qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
	m_qp = ibv_create_qp(m_p_ib_ctx_handler->get_ibv_pd(), &qp_init_attr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_qp) {
		validate_raw_qp_privliges();
		qp_logerr("ibv_create_qp failed (errno=%d %m)", errno);
		return -1;
	}

	if ((ret = priv_ibv_modify_qp_from_err_to_init_raw(m_qp, m_port_num)) != 0) {
		qp_logerr("failed to modify QP from ERR to INIT state (ret = %d)", ret);
		return ret;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

void qp_mgr_ib::modify_qp_to_ready_state()
{
	qp_logdbg("");
	int ret = 0;
	int qp_state = priv_ibv_query_qp_state(m_qp);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (qp_state !=  IBV_QPS_INIT) {
		if ((ret = priv_ibv_modify_qp_from_err_to_init_ud(m_qp, m_port_num, m_pkey_index)) != 0) {
			qp_logpanic("failed to modify QP from %d to RTS state (ret = %d)", qp_state, ret);
		}
	}
	if ((ret = priv_ibv_modify_qp_from_init_to_rts(m_qp)) != 0) {
		qp_logpanic("failed to modify QP from INIT to RTS state (ret = %d)", ret);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

int qp_mgr_ib::prepare_ibv_qp(struct ibv_qp_init_attr& qp_init_attr)
{
	qp_logdbg("");
	int ret = 0;
	qp_init_attr.qp_type = IBV_QPT_UD;
	m_qp = ibv_create_qp(m_p_ib_ctx_handler->get_ibv_pd(), &qp_init_attr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_qp) {
		qp_logerr("ibv_create_qp failed (errno=%d %m)", errno);
		return -1;
	}

	if ((ret = priv_ibv_modify_qp_from_err_to_init_ud(m_qp, m_port_num, m_pkey_index)) != 0) {
		VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "failed to modify QP from ERR to INIT state (ret = %d) check number of available fds (ulimit -n)", ret, errno);
		return ret;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

void qp_mgr_ib::update_pkey_index()
{
	qp_logdbg("");
	if (priv_ibv_find_pkey_index(m_p_ib_ctx_handler->get_ibv_context(), get_port_num(), m_pkey, &m_pkey_index)) {
		qp_logdbg("IB: Can't find correct pkey_index for pkey '%d'", m_pkey);
		m_pkey_index = (uint16_t)-1;
	}
	else {
		qp_logdbg("IB: Found correct pkey_index (%d) for pkey '%d'", m_pkey_index, m_pkey);
	}
}
