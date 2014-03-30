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


#include "cq_mgr.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/ip.h>

#include <vma/util/vtypes.h>
#include <vma/util/valgrind.h>
#include <vma/util/verbs_extra.h>
#include <vma/sock/sock-redirect.h>
#include "vma/util/bullseye.h"

#include "buffer_pool.h"
#include "qp_mgr.h"

#include "vma/util/instrumentation.h"

#define BUFF_STAT_REFRESH	65536
#define BUFF_STAT_THRESHOLD	8

#define MODULE_NAME 		"cqm"

#define cq_logpanic 		__log_info_panic
#define cq_logerr		__log_info_err
#define cq_logwarn		__log_info_warn
#define cq_loginfo		__log_info_info
#define cq_logdbg		__log_info_dbg
#define cq_logfunc		__log_info_func
#define cq_logfuncall		__log_info_funcall

#define cq_logdbg_no_funcname(log_fmt, log_args...)	do { if (g_vlogger_level >= VLOG_DEBUG) 	vlog_printf(VLOG_DEBUG, MODULE_NAME "[%p]:%d: "  log_fmt "\n", __INFO__, __LINE__, ##log_args); } while (0)

atomic_t cq_mgr::m_n_cq_id_counter = ATOMIC_DECLARE_INIT(1);
uint64_t cq_mgr::m_n_global_sn = 0;

cq_mgr::cq_mgr(ring* p_ring, ib_ctx_handler* p_ib_ctx_handler, int cq_size, struct ibv_comp_channel* p_comp_event_channel, bool is_rx) :
		m_p_ring(p_ring), m_p_ib_ctx_handler(p_ib_ctx_handler), m_b_is_rx(is_rx), m_comp_event_channel(p_comp_event_channel), m_p_next_rx_desc_poll(NULL)
{
	cq_logfunc("");

	m_n_wce_counter = 0;
	m_b_was_drained = false;

	m_b_notification_armed = false;
	m_n_out_of_free_bufs_warning = 0;

	m_n_cq_poll_sn = 0;
	m_cq_id = atomic_fetch_and_inc(&m_n_cq_id_counter); // cq id is nonzero

	m_transport_type = m_p_ring->get_transport_type();

	m_p_ibv_cq = ibv_create_cq(m_p_ib_ctx_handler->get_ibv_context(), cq_size, (void*)this, m_comp_event_channel, 0);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_ibv_cq) {
		cq_logpanic("ibv_create_cq failed (errno=%d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	
	// use local copy of stats by default (on rx cq get shared memory stats)
	m_p_cq_stat = &m_cq_stat_static;
	memset(m_p_cq_stat , 0, sizeof(*m_p_cq_stat));
/*
	m_p_cq_stat->n_rx_sw_queue_len = 0;
	m_p_cq_stat->n_rx_pkt_drop = 0;
	m_p_cq_stat->n_rx_drained_at_once_max = 0;
	m_p_cq_stat->n_buffer_pool_len = 0;
	m_p_cq_stat->buffer_miss_rate = 0.0;
//*/
	m_buffer_miss_count = 0;
	m_buffer_total_count = 0;
	m_buffer_prev_id = 0;

	m_sz_transport_header = 0;
	switch (m_transport_type) {
	case VMA_TRANSPORT_IB:
		m_sz_transport_header = GRH_HDR_LEN;
		break;
	case VMA_TRANSPORT_ETH:
		m_sz_transport_header = ETH_HDR_LEN;
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		cq_logpanic("Unknown transport type: %d", m_transport_type);
		break;
	BULLSEYE_EXCLUDE_BLOCK_END
	}

	if (m_b_is_rx)
		vma_stats_instance_create_cq_block(m_p_cq_stat);

	cq_logdbg("Created CQ as %s with fd[%d] and of size %d elements (ibv_cq_hndl=%p)", (m_b_is_rx?"Rx":"Tx"), get_channel_fd(), cq_size, m_p_ibv_cq);
}

cq_mgr::~cq_mgr()
{
	cq_logdbg("destroying CQ as %s", (m_b_is_rx?"Rx":"Tx"));

	int ret = 0;
	uint32_t ret_total = 0;
	uint64_t cq_poll_sn = 0;
	mem_buf_desc_t* buff = NULL;
	struct ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
	while ((ret = poll(wce, MCE_MAX_CQ_POLL_BATCH, &cq_poll_sn)) > 0) {
		for (int i = 0; i < ret; i++) {
			if (m_b_is_rx) {
				buff = process_cq_element_rx(&wce[i]);
			} else {
				buff = process_cq_element_tx(&wce[i]);
			}
			if (buff)
				m_rx_queue.push_back(buff);
		}
		ret_total += ret;
	}
	m_b_was_drained = true;
	if (ret_total > 0) {
		cq_logdbg("Drained %d wce", ret_total);
	}

	if (m_rx_queue.size() + m_rx_pool.size()) {
		cq_logdbg("Returning %d buffers to global Rx pool (ready queue %d, free pool %d))", m_rx_queue.size() + m_rx_pool.size(), m_rx_queue.size(), m_rx_pool.size());

		g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_queue, m_rx_queue.size());
		m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();

		g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_pool, m_rx_pool.size());
		m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
	}

	cq_logfunc("destroying ibv_cq");
	IF_VERBS_FAILURE(ibv_destroy_cq(m_p_ibv_cq)) {
		cq_logerr("destroy cq failed (errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;

	statistics_print();
	if (m_b_is_rx)
		vma_stats_instance_remove_cq_block(m_p_cq_stat);

	cq_logdbg("done");
}

void cq_mgr::statistics_print()
{
	if (m_p_cq_stat->n_rx_pkt_drop || m_p_cq_stat->n_rx_sw_queue_len || 
	    m_p_cq_stat->n_rx_drained_at_once_max || m_p_cq_stat->n_buffer_pool_len) {
		cq_logdbg_no_funcname("Packets dropped: %12llu", m_p_cq_stat->n_rx_pkt_drop);
		cq_logdbg_no_funcname("Drained max: %17u",  m_p_cq_stat->n_rx_drained_at_once_max);
		cq_logdbg_no_funcname("Buffer disorder: %11.2f%%", m_p_cq_stat->buffer_miss_rate*100);
	}
}

ibv_cq* cq_mgr::get_ibv_cq_hndl()
{
	return m_p_ibv_cq;
}

int cq_mgr::get_channel_fd()
{
	return m_comp_event_channel->fd;
}

void cq_mgr::add_qp_rx(qp_mgr* qp)
{
	cq_logdbg("qp_mgr=%p", qp);
	mem_buf_desc_t *p_temp_desc_list, *p_temp_desc_next;

	m_p_cq_stat->n_rx_drained_at_once_max = 0;

	// Initial fill of receiver work requests
	uint32_t qp_rx_wr_num = qp->get_rx_max_wr_num();
	cq_logdbg("Trying to push %d WRE to allocated qp (%p)", qp_rx_wr_num, qp);
	while (qp_rx_wr_num) {
		uint32_t n_num_mem_bufs = mce_sys.rx_num_wr_to_post_recv;
		if (n_num_mem_bufs > qp_rx_wr_num)
			n_num_mem_bufs = qp_rx_wr_num;
		p_temp_desc_list = g_buffer_pool_rx->get_buffers_thread_safe(n_num_mem_bufs, m_p_ib_ctx_handler);
		if (p_temp_desc_list == NULL) {
			cq_logwarn("Out of mem_buf_desc from Rx buffer pool for qp_mgr qp_mgr initialization (qp=%p)", qp);
			cq_logwarn("This might happen due to wrong setting of VMA_RX_BUFS and VMA_RX_WRE. Please refer to README.txt for more info");
			break;
		}

		p_temp_desc_next = p_temp_desc_list;
		while (p_temp_desc_next) {
			p_temp_desc_next->p_desc_owner = m_p_ring;
			p_temp_desc_next = p_temp_desc_next->p_next_desc;
		}

		if (qp->post_recv(p_temp_desc_list) != 0) {
			cq_logdbg("qp post recv is already full (push=%d, planned=%d)", qp->get_rx_max_wr_num()-qp_rx_wr_num, qp->get_rx_max_wr_num());
			g_buffer_pool_rx->put_buffers_thread_safe(p_temp_desc_list);
			break;
		}
		qp_rx_wr_num -= n_num_mem_bufs;
	}
	cq_logdbg("Successfully post_recv qp with %d new Rx buffers (planned=%d)", qp->get_rx_max_wr_num()-qp_rx_wr_num, qp->get_rx_max_wr_num());

	// Add qp_mgr to map
	m_qp_rec.qp = qp;
	m_qp_rec.debth = 0;
}

void cq_mgr::del_qp_rx(qp_mgr *qp)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_qp_rec.qp != qp) {
		cq_logdbg("wrong qp_mgr=%p != m_qp_rec.qp=%p", qp, m_qp_rec.qp);
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	cq_logdbg("qp_mgr=%p", m_qp_rec.qp);
	return_extra_buffers();
	memset(&m_qp_rec, 0, sizeof(m_qp_rec));
}

void cq_mgr::add_qp_tx(qp_mgr* qp)
{
	//Assume locked!
	cq_logdbg("qp_mgr=%p", qp);

	m_qp_rec.qp = qp;
	m_qp_rec.debth = 0;
}

bool cq_mgr::request_more_buffers()
{
	mem_buf_desc_t *p_temp_desc_list, *p_temp_buff;

	cq_logfuncall("Allocating additional %d buffers for internal use", mce_sys.qp_compensation_level);

	// Assume locked!
	// Add an additional free buffer descs to RX cq mgr
	p_temp_desc_list = g_buffer_pool_rx->get_buffers_thread_safe(mce_sys.qp_compensation_level, m_p_ib_ctx_handler);
	if (p_temp_desc_list == NULL) {
		cq_logfunc("Out of mem_buf_desc from RX free pool for internal object pool");
		return false;
	}

	while (p_temp_desc_list) {
		p_temp_buff = p_temp_desc_list;
		p_temp_desc_list = p_temp_buff->p_next_desc;
		p_temp_buff->p_desc_owner = m_p_ring;
		p_temp_buff->p_next_desc = NULL;
		m_rx_pool.push_back(p_temp_buff);
	}

	m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
	return true;
}

void cq_mgr::return_extra_buffers()
{
	if (m_rx_pool.size() < mce_sys.qp_compensation_level * 2)
		return;
	int buff_to_rel = m_rx_pool.size() - mce_sys.qp_compensation_level;

	cq_logfunc("releasing %d buffers to global rx pool", buff_to_rel);
	g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_pool, buff_to_rel);
	m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
}

int cq_mgr::poll(ibv_wc* p_wce, int num_entries, uint64_t* p_cq_poll_sn)
{
	// Assume locked!!!
	cq_logfuncall("");

	int ret = ibv_poll_cq(m_p_ibv_cq, num_entries, p_wce);
	if (ret <= 0) {
		// Zero polled wce    OR    ibv_poll_cq() has driver specific errors
		// so we can't really do anything with them
		*p_cq_poll_sn = m_n_global_sn;
#ifdef VMA_TIME_MEASURE
		INC_ERR_POLL_COUNT;
#endif
		return 0;
	}

#ifdef VMA_TIME_MEASURE
	TAKE_POLL_CQ_IN;
#endif

	if (unlikely(g_vlogger_level >= VLOG_FUNC_ALL)) {
		for (int i = 0; i < ret; i++) {
			cq_logfuncall("wce[%d] info wr_id=%x, status=%x, opcode=%x, vendor_err=%x, byte_len=%d, imm_data=%x", i, p_wce[i].wr_id, p_wce[i].status, p_wce[i].opcode, p_wce[i].vendor_err, p_wce[i].byte_len, p_wce[i].imm_data);
			cq_logfuncall("qp_num=%x, src_qp=%x, wc_flags=%x, pkey_index=%x, slid=%x, sl=%x, dlid_path_bits=%x", p_wce[i].qp_num, p_wce[i].src_qp, p_wce[i].wc_flags, p_wce[i].pkey_index, p_wce[i].slid, p_wce[i].sl, p_wce[i].dlid_path_bits);
		}
	}

	// spoil the global sn if we have packets ready
	union __attribute__((packed)) {
		uint64_t global_sn;
		struct {
			uint32_t cq_id;
			uint32_t cq_sn;
		} bundle;
	} next_sn;
	next_sn.bundle.cq_sn = ++m_n_cq_poll_sn;
	next_sn.bundle.cq_id = m_cq_id;

	*p_cq_poll_sn = m_n_global_sn = next_sn.global_sn;		

	return ret;
}

void cq_mgr::process_cq_element_log_helper(mem_buf_desc_t* p_mem_buf_desc, struct ibv_wc* p_wce)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	// wce with bad status value
	if (p_wce->status != IBV_WC_WR_FLUSH_ERR) {
		cq_logwarn("wce: wr_id=%#x, status=%#x, vendor_err=%#x, qp_num=%#x", p_wce->wr_id, p_wce->status, p_wce->vendor_err, p_wce->qp_num);
		cq_loginfo("wce: opcode=%#x, byte_len=%#d, src_qp=%#x, wc_flags=%#x", p_wce->opcode, p_wce->byte_len, p_wce->src_qp, p_wce->wc_flags);
		cq_loginfo("wce: pkey_index=%#x, slid=%#x, sl=%#x, dlid_path_bits=%#x, imm_data=%#x", p_wce->pkey_index, p_wce->slid, p_wce->sl, p_wce->dlid_path_bits, p_wce->imm_data);

		if (p_mem_buf_desc) {
			cq_logwarn("mem_buf_desc: lkey=%#x, p_buffer=%p, sz_buffer=%#x", p_mem_buf_desc->lkey, p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_buffer);
		}
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	cq_logfunc("wce error status '%s' [%d] (wr_id=%p, qp_num=%x)", priv_ibv_wc_status_str(p_wce->status), p_wce->status, p_wce->wr_id, p_wce->qp_num);
}

mem_buf_desc_t* cq_mgr::process_cq_element_tx(struct ibv_wc* p_wce)
{
	// Assume locked!!!
	cq_logfuncall("");

	// Get related mem_buf_desc pointer from the wr_id
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(uintptr_t)p_wce->wr_id;

	if (unlikely(p_wce->status != IBV_WC_SUCCESS)) {
		process_cq_element_log_helper(p_mem_buf_desc, p_wce);

		if (p_mem_buf_desc == NULL) {
			cq_logdbg("wce->wr_id = 0!!! When status != IBV_WC_SUCCESS");
			return NULL;
		}
		if (p_mem_buf_desc->p_desc_owner) {
			p_mem_buf_desc->p_desc_owner->mem_buf_desc_completion_with_error_tx(p_mem_buf_desc);
			return NULL;
		}
		// AlexR: can this wce have a valid mem_buf_desc pointer?
		// AlexR: are we throwing away a data buffer and a mem_buf_desc element?
		cq_logdbg("no desc_owner(wr_id=%p, qp_num=%x)", p_wce->wr_id, p_wce->qp_num);
		return NULL;
	}

	if (p_mem_buf_desc == NULL) {
		cq_logdbg("wce->wr_id = 0!!! When status == IBV_WC_SUCCESS");
		return NULL;
	}

	return p_mem_buf_desc;
}

mem_buf_desc_t* cq_mgr::process_cq_element_rx(struct ibv_wc* p_wce)
{
	// Assume locked!!!
	cq_logfuncall("");

	// Get related mem_buf_desc pointer from the wr_id
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(uintptr_t)p_wce->wr_id;

	if (unlikely(p_wce->status != IBV_WC_SUCCESS)) {
		process_cq_element_log_helper(p_mem_buf_desc, p_wce);

		m_p_next_rx_desc_poll = NULL;

		if (p_mem_buf_desc == NULL) {
			cq_logdbg("wce->wr_id = 0!!! When status != IBV_WC_SUCCESS");
			return NULL;
		}
		if (p_mem_buf_desc->p_desc_owner) {
			p_mem_buf_desc->p_desc_owner->mem_buf_desc_completion_with_error_rx(p_mem_buf_desc);
			return NULL;
		}
		// AlexR: can this wce have a valid mem_buf_desc pointer?
		// AlexR: are we throwing away a data buffer and a mem_buf_desc element?
		cq_logdbg("no desc_owner(wr_id=%p, qp_num=%x)", p_wce->wr_id, p_wce->qp_num);
		return NULL;
	}

	if (p_mem_buf_desc == NULL) {
		m_p_next_rx_desc_poll = NULL;
		cq_logdbg("wce->wr_id = 0!!! When status == IBV_WC_SUCCESS");
		return NULL;
	}

	if (mce_sys.rx_prefetch_bytes_before_poll) {
		/*for debug:
		if (m_p_next_rx_desc_poll && m_p_next_rx_desc_poll != p_mem_buf_desc) {
			cq_logerr("prefetched wrong buffer");
		}*/
		m_p_next_rx_desc_poll = p_mem_buf_desc->p_prev_desc;
		p_mem_buf_desc->p_prev_desc = NULL;
	}

	if (p_wce->opcode & IBV_WC_RECV) {
		p_mem_buf_desc->path.rx.qpn = p_wce->qp_num;
#if 0 // Removed VLAN support in VMA, until we start using the new OFED vlan scheme.
		if(p_wce->wc_flags & IBV_WC_WITH_VLAN) {
			p_mem_buf_desc->path.rx.vlan = p_wce->pkey_index;
			//cq_logfunc("qpn %u p_wce->pkey_index %d p_wce->sl %d", p_mem_buf_desc->path.rx.qpn, p_mem_buf_desc->path.rx.vlan, p_wce->sl >> 1);
		}
		else
#endif
			p_mem_buf_desc->path.rx.vlan = 0;
		// Save recevied total bytes
		p_mem_buf_desc->sz_data = p_wce->byte_len;

		//we use context to verify that on reclaim rx buffer path we return the buffer to the right CQ
		p_mem_buf_desc->path.rx.context = this;

		VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

		prefetch_range((uint8_t*)p_mem_buf_desc->p_buffer + m_sz_transport_header, 
				min(p_mem_buf_desc->sz_data - m_sz_transport_header, (size_t)mce_sys.rx_prefetch_bytes));
		//prefetch((uint8_t*)p_mem_buf_desc->p_buffer + m_sz_transport_header);
	}

	return p_mem_buf_desc;
}

inline int cq_mgr::post_recv_qp(qp_rec *qprec, mem_buf_desc_t *buff)
{
	if (buff->serial_num > m_buffer_prev_id + BUFF_STAT_THRESHOLD)
		++m_buffer_miss_count;
	m_buffer_prev_id = buff->serial_num;
	++m_buffer_total_count;

	if (m_buffer_total_count >= BUFF_STAT_REFRESH) {
		m_p_cq_stat->buffer_miss_rate = m_buffer_miss_count/(double)m_buffer_total_count;
		m_buffer_miss_count = 0;
		m_buffer_total_count = 0;
	}
	// buff->p_next_desc = NULL;
	return qprec->qp->post_recv(buff);
}

bool cq_mgr::compensate_qp_post_recv(mem_buf_desc_t* buff_cur)
{
	// Assume locked!!!
	// Compensate QP for all completions that we found
	if (m_qp_rec.qp) {
		++m_qp_rec.debth;
		if (m_rx_pool.size() || request_more_buffers()) {
			do {
				mem_buf_desc_t *buff_new = m_rx_pool.front();
				m_rx_pool.pop_front();
				post_recv_qp(&m_qp_rec, buff_new);
			} while (--m_qp_rec.debth > 0 && m_rx_pool.size());
			m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
		}
		else if (mce_sys.cq_keep_qp_full ||
				m_qp_rec.debth + MCE_MAX_CQ_POLL_BATCH > (int)m_qp_rec.qp->get_rx_max_wr_num()) {

			m_p_cq_stat->n_rx_pkt_drop++;
			post_recv_qp(&m_qp_rec, buff_cur);
			--m_qp_rec.debth;
			return true;
		}
	}
	return false;
}

void cq_mgr::reclaim_recv_buffer_helper(mem_buf_desc_t* buff)
{
	// Assume locked!!!
	if (buff->dec_ref_count() <= 0 && (buff->lwip_pbuf.pbuf.ref-- <= 1)) {
		//we need to verify that the buffer is returned to the right CQ (in case of HA ring's active CQ can change)
		if (likely(buff->path.rx.context == this)) {
			mem_buf_desc_t* temp = NULL;
			while (buff) {
				temp = buff;
				buff = temp->p_next_desc;
				temp->p_next_desc = NULL;
				temp->p_prev_desc = NULL;
				temp->reset_ref_count();
				temp->path.rx.gro = 0;
				temp->path.rx.p_ip_h = NULL;
				temp->path.rx.p_tcp_h = NULL;
				temp->path.rx.timestamp.tv_nsec = 0;
				temp->path.rx.timestamp.tv_sec = 0;
				free_lwip_pbuf(&temp->lwip_pbuf);
				m_rx_pool.push_back(temp);
			}
			m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
		}
		else {
			cq_logfunc("Buffer returned to wrong CQ");
			g_buffer_pool_rx->put_buffers_thread_safe(buff);
		}
	}
}

uint32_t cq_mgr::process_recv_queue(void* pv_fd_ready_array)
{
	// Assume locked!!!
	// If we have packets in the queue, dequeue one and process it
	// until reaching cq_poll_batch_max or empty queue
	uint32_t processed = 0;

	while (!m_rx_queue.empty()) {
		mem_buf_desc_t* buff = m_rx_queue.front();
		m_rx_queue.pop_front();
		process_recv_buffer(buff, pv_fd_ready_array);
		if (++processed >= mce_sys.cq_poll_batch_max)
			break;
	}
	m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
	return processed;
}

inline void cq_mgr::process_recv_buffer(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array)
{
	// Assume locked!!!

	// Pass the Rx buffer ib_comm_mgr for further IP processing
	if (!m_p_ring->rx_process_buffer(p_mem_buf_desc, m_transport_type, pv_fd_ready_array)) {
		// If buffer is dropped by callback - return to RX pool
		reclaim_recv_buffer_helper(p_mem_buf_desc);
	}
}

void cq_mgr::process_tx_buffer_list(mem_buf_desc_t* p_mem_buf_desc)
{
	// Assume locked!!!
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_mem_buf_desc && p_mem_buf_desc->p_desc_owner == m_p_ring) {
		p_mem_buf_desc->p_desc_owner->mem_buf_desc_return_to_owner_tx(p_mem_buf_desc);
	}
	else {
		cq_logerr("got error %p %p", p_mem_buf_desc, p_mem_buf_desc ? p_mem_buf_desc->p_desc_owner : NULL);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

void cq_mgr::mem_buf_desc_completion_with_error(mem_buf_desc_t* p_mem_buf_desc)
{
	cq_logfuncall("");
	// lock(); Called from cq_mgr context which is already locked!!
	reclaim_recv_buffer_helper(p_mem_buf_desc);
	// unlock(); Called from cq_mgr context which is already locked!!
}

void cq_mgr::mem_buf_desc_return_to_owner(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array /*=NULL*/)
{
	cq_logfuncall("");
	NOT_IN_USE(pv_fd_ready_array);
	reclaim_recv_buffer_helper(p_mem_buf_desc);
}

int cq_mgr::poll_and_process_helper_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	// Assume locked!!!
	cq_logfuncall("");
	struct ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];

	int ret;
	uint32_t ret_rx_processed = process_recv_queue(pv_fd_ready_array);
	if (ret_rx_processed >= mce_sys.cq_poll_batch_max) {
		goto out;
	}

	if (m_p_next_rx_desc_poll) {
		prefetch_range((uint8_t*)m_p_next_rx_desc_poll->p_buffer,mce_sys.rx_prefetch_bytes_before_poll);
	}

	ret = poll(wce, mce_sys.cq_poll_batch_max, p_cq_poll_sn);
	if (ret > 0) {
		m_n_wce_counter += ret;
		if (ret < (int)mce_sys.cq_poll_batch_max)
			m_b_was_drained = true;

		for (int i = 0; i < ret; i++) {
			mem_buf_desc_t *buff = process_cq_element_rx((&wce[i]));
			if (buff) {
				if (wce[i].opcode & IBV_WC_RECV) {
					if (!compensate_qp_post_recv(buff)) {
						process_recv_buffer(buff, pv_fd_ready_array);
					}
				}
			}
		}
		ret_rx_processed += ret;
	}

out:
	m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
	return ret_rx_processed;
}

int cq_mgr::poll_and_process_helper_tx(uint64_t* p_cq_poll_sn)
{
	// Assume locked!!!
	cq_logfuncall("");
	struct ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
	int ret = poll(wce, mce_sys.cq_poll_batch_max, p_cq_poll_sn);
	if (ret > 0) {
		m_n_wce_counter += ret;
		if (ret < (int)mce_sys.cq_poll_batch_max)
			m_b_was_drained = true;

		for (int i = 0; i < ret; i++) {
			mem_buf_desc_t *buff = process_cq_element_tx((&wce[i]));
			if (buff) {
				process_tx_buffer_list(buff);
			}
		}
	}
	return ret;
}

int cq_mgr::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*=NULL*/)
{
	cq_logfuncall("");
	return poll_and_process_helper_rx(p_cq_poll_sn, pv_fd_ready_array);
}

int cq_mgr::poll_and_process_element_tx(uint64_t* p_cq_poll_sn)
{
	cq_logfuncall("");
	return poll_and_process_helper_tx(p_cq_poll_sn);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

bool cq_mgr::reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst)
{
	if (likely(rx_reuse_lst)) {
		reclaim_recv_buffer_helper(rx_reuse_lst);
		return true;
	}
	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

bool cq_mgr::reclaim_recv_buffers_no_lock(std::deque<mem_buf_desc_t*> *rx_reuse)
{
	//Assume locked
	cq_logfuncall("");
	while (!rx_reuse->empty()) {
		reclaim_recv_buffer_helper(rx_reuse->front());
		rx_reuse->pop_front();
	}
	//return_extra_buffers();

	return true;
}

bool cq_mgr::reclaim_recv_buffers(std::deque<mem_buf_desc_t*> *rx_reuse)
{
	cq_logfuncall("");
	// Called from outside cq_mgr context which is not locked!!
	while (!rx_reuse->empty()) {
		reclaim_recv_buffer_helper(rx_reuse->front());
		rx_reuse->pop_front();
	}
	return_extra_buffers();

	return true;
}

inline bool is_ib_tcp_frame(mem_buf_desc_t* buff)
{
        struct ipoibhdr* p_ipoib_h = (struct ipoibhdr*)(buff->p_buffer + GRH_HDR_LEN);

        // Validate IPoIB header
        if (unlikely(p_ipoib_h->ipoib_header != htonl(IPOIB_HEADER))) {
                return false;
        }

        size_t transport_header_len = GRH_HDR_LEN + IPOIB_HDR_LEN;

        struct iphdr * p_ip_h = (struct iphdr*)(buff->p_buffer + transport_header_len);
        if (likely(p_ip_h->protocol == IPPROTO_TCP)) {
                return true;
        }
        return false;
}

inline bool is_eth_tcp_frame(mem_buf_desc_t* buff)
{
	struct ethhdr* p_eth_h = (struct ethhdr*)(buff->p_buffer);
	uint16_t* p_h_proto = &p_eth_h->h_proto;

	size_t transport_header_len = ETH_HDR_LEN;
	struct vlanhdr* p_vlan_hdr = NULL;
	if (*p_h_proto == htons(ETH_P_8021Q)) {
		p_vlan_hdr = (struct vlanhdr*)((uint8_t*)p_eth_h + transport_header_len);
		transport_header_len = ETH_VLAN_HDR_LEN;
		p_h_proto = &p_vlan_hdr->h_vlan_encapsulated_proto;
	}
	struct iphdr *p_ip_h = (struct iphdr*)(buff->p_buffer + transport_header_len);
	if (likely(*p_h_proto == htons(ETH_P_IP)) && (p_ip_h->protocol == IPPROTO_TCP)) {
		return true;
	}
	return false;
}

int cq_mgr::drain_and_proccess(bool b_recycle_buffers /*=false*/)
{
	cq_logfuncall("cq was %s drained. %d processed wce since last check. %d wce in m_rx_queue", (m_b_was_drained?"":"not "), m_n_wce_counter, m_rx_queue.size());

	// CQ polling loop until max wce limit is reached for this interval or CQ is drained
	uint32_t ret_total = 0;
	uint64_t cq_poll_sn = 0;

	if (b_recycle_buffers)
		m_b_was_drained = false;

	while ((mce_sys.progress_engine_wce_max && (mce_sys.progress_engine_wce_max > m_n_wce_counter)) && 
		!m_b_was_drained) {

		struct ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
		int ret = poll(wce, MCE_MAX_CQ_POLL_BATCH, &cq_poll_sn);
		if (ret <= 0) {
			m_b_was_drained = true;
			m_p_ring->m_gro_mgr.flush_all(NULL);
			return ret_total;
		}

		m_n_wce_counter += ret;
		if (ret < MCE_MAX_CQ_POLL_BATCH)
			m_b_was_drained = true;

		for (int i = 0; i < ret; i++) {
			mem_buf_desc_t* buff = process_cq_element_rx(&wce[i]);
			if (buff) {
				if (b_recycle_buffers) {
					m_p_cq_stat->n_rx_pkt_drop++;
					reclaim_recv_buffer_helper(buff);
				} else {
					bool procces_now = false;
					if (m_transport_type == VMA_TRANSPORT_ETH) {
						procces_now = is_eth_tcp_frame(buff);
					}
					if (m_transport_type == VMA_TRANSPORT_IB) {
						procces_now = is_ib_tcp_frame(buff);
					}
					// We process immediately all non udp/ip traffic..
					if (procces_now) {
						if (!compensate_qp_post_recv(buff)) {
							process_recv_buffer(buff, NULL);
						}
					}
					else { //udp/ip traffic we just put in the cq's rx queueu
						m_rx_queue.push_back(buff);
						if (compensate_qp_post_recv(m_rx_queue.front())) {
							m_rx_queue.pop_front();
						}
					}
				}
			}
		}
		ret_total += ret;
	}
	m_p_ring->m_gro_mgr.flush_all(NULL);

	m_n_wce_counter = 0;
	m_b_was_drained = false;

	// Update cq statistics
	m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
	m_p_cq_stat->n_rx_drained_at_once_max = max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

	return ret_total;
}


int cq_mgr::request_notification(uint64_t poll_sn)
{
	int ret = -1;
	cq_logfuncall("");

	if (m_n_global_sn > 0 && poll_sn != m_n_global_sn) {
		// The cq_mgr's has receive packets pending processing (or got processed since cq_poll_sn)
		cq_logfunc("miss matched poll sn (user=0x%lx, cq=0x%lx)", poll_sn, m_n_cq_poll_sn);
		return 1;
	}

	if (m_b_notification_armed == false) {

		cq_logfunc("arming cq_mgr notification channel");

		// Arm the CQ notification channel
		IF_VERBS_FAILURE(ibv_req_notify_cq(m_p_ibv_cq, 0)) {
			cq_logerr("Failure arming the qp_mgr notification channel (errno=%d %m)", errno);
		}
		else {
			ret = 0;
			m_b_notification_armed = true;

		} ENDIF_VERBS_FAILURE;
	}
	else {
		// cq_mgr notification channel already armed
		ret = 0;
	}

	cq_logfuncall("returning with %d", ret);
	return ret;
}

int cq_mgr::wait_for_notification_and_process_element(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	cq_logfunc("");

	int ret = -1;
	if (m_b_notification_armed) {
		cq_mgr* p_cq_mgr_context = NULL;
		struct ibv_cq* p_cq_hndl = NULL;
		void *p; // deal with compiler warnings

		// Block on the cq_mgr's notification event channel
		IF_VERBS_FAILURE(ibv_get_cq_event(m_comp_event_channel, &p_cq_hndl, &p)) {
			cq_logfunc("waiting on cq_mgr event returned with error (errno=%d %m)", errno);
		}
		else {
			p_cq_mgr_context = (cq_mgr*)p;
			if (p_cq_mgr_context != this) {
				cq_logerr("mismatch with cq_mgr returned from new event (event->cq_mgr->%p)", p_cq_mgr_context);
				// this can be if we are using a single channel for several/all cq_mgrs
				// in this case we need to deliver the event to the correct cq_mgr
			}

			// Ack event
			ibv_ack_cq_events(m_p_ibv_cq, 1);

			// Clear flag
			m_b_notification_armed = false;

			// Now try processing the ready element
			if (m_b_is_rx) {
				ret = poll_and_process_helper_rx(p_cq_poll_sn, pv_fd_ready_array);
			} else {
				ret = poll_and_process_helper_tx(p_cq_poll_sn);
			}
		} ENDIF_VERBS_FAILURE;
	}
	else {
		cq_logfunc("notification channel is not armed");
		errno = EAGAIN;
	}

	return ret;
}

cq_mgr* get_cq_mgr_from_cq_event(struct ibv_comp_channel* p_cq_channel)
{
	cq_mgr* p_cq_mgr = NULL;
	struct ibv_cq* p_cq_hndl = NULL;
	void *p_context; // deal with compiler warnings

	// read & ack the CQ event
	IF_VERBS_FAILURE(ibv_get_cq_event(p_cq_channel, &p_cq_hndl, &p_context)) {
		vlog_printf(VLOG_INFO, MODULE_NAME ":%d: waiting on cq_mgr event returned with error (errno=%d %m)\n", __LINE__, errno);
	}
	else {
		p_cq_mgr = (cq_mgr*)p_context; // Save the cq_mgr
		ibv_ack_cq_events(p_cq_hndl, 1); // Ack the ibv event
	} ENDIF_VERBS_FAILURE;

	return p_cq_mgr;
}

void cq_mgr::modify_cq_moderation(uint32_t period, uint32_t count)
{
#ifdef DEFINED_IBV_EXP_CQ_MODERATION
	struct ibv_exp_cq_attr cq_attr;
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.comp_mask = IBV_EXP_CQ_ATTR_MODERATION;
	cq_attr.moderation.cq_count = count;
	cq_attr.moderation.cq_period = period;

	cq_logfunc("modify cq moderation, period=%d, count=%d", period, count);

	IF_VERBS_FAILURE(ibv_exp_modify_cq(m_p_ibv_cq, &cq_attr, IBV_EXP_CQ_MODERATION)) {
		cq_logerr("Failure modifying cq moderation (errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;
#else
	NOT_IN_USE(count);
	NOT_IN_USE(period);
#endif
}
