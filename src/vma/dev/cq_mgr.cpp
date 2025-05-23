/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "cq_mgr.h"
#include "cq_mgr.inl"
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/ip.h>

#include "utils/bullseye.h"
#include <vma/util/vtypes.h>
#include <vma/util/valgrind.h>
#include "vma/util/instrumentation.h"
#include <vma/sock/sock-redirect.h>
#include "vma/ib/base/verbs_extra.h"

#include "buffer_pool.h"
#include "qp_mgr.h"
#include "ring_simple.h"

#define MODULE_NAME 		"cqm"

#define cq_logpanic     __log_info_panic
#define cq_logerr       __log_info_err
#define cq_logwarn      __log_info_warn
#define cq_loginfo      __log_info_info
#define cq_logdbg       __log_info_dbg
#define cq_logfunc      __log_info_func
#define cq_logfuncall   __log_info_funcall

#define cq_logdbg_no_funcname(log_fmt, log_args...) do { if (g_vlogger_level >= VLOG_DEBUG) vlog_printf(VLOG_DEBUG, MODULE_NAME "[%p]:%d: " log_fmt "\n", __INFO__, __LINE__, ##log_args); } while (0)

#if VLIST_DEBUG
#define VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER do { 	\
		if (buff->buffer_node.is_list_member())         \
			cq_logwarn("Buffer is already a member in a list! id=[%s]", buff->buffer_node.list_id()); \
		} while (0)
#else
#define VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER
#endif

atomic_t cq_mgr::m_n_cq_id_counter = ATOMIC_INIT(1);

uint64_t cq_mgr::m_n_global_sn = 0;

cq_mgr::cq_mgr(ring_simple* p_ring, ib_ctx_handler* p_ib_ctx_handler, int cq_size, struct ibv_comp_channel* p_comp_event_channel, bool is_rx, bool config) :
	m_p_ibv_cq(NULL)
	,m_b_is_rx(is_rx)
	,m_cq_id(0)
	,m_n_cq_poll_sn(0)
	,m_p_ring(p_ring)
	,m_n_wce_counter(0)
	,m_b_was_drained(false)
	,m_b_is_rx_hw_csum_on(false)
	,m_n_sysvar_cq_poll_batch_max(safe_mce_sys().cq_poll_batch_max)
	,m_n_sysvar_progress_engine_wce_max(safe_mce_sys().progress_engine_wce_max)
	,m_p_cq_stat(&m_cq_stat_static) // use local copy of stats by default (on rx cq get shared memory stats)
	,m_transport_type(m_p_ring->get_transport_type())
	,m_p_next_rx_desc_poll(NULL)
	,m_n_sysvar_rx_prefetch_bytes_before_poll(safe_mce_sys().rx_prefetch_bytes_before_poll)
	,m_n_sysvar_rx_prefetch_bytes(safe_mce_sys().rx_prefetch_bytes)
	,m_sz_transport_header(0)
	,m_p_ib_ctx_handler(p_ib_ctx_handler)
	,m_n_sysvar_rx_num_wr_to_post_recv(safe_mce_sys().rx_num_wr_to_post_recv)
	,m_comp_event_channel(p_comp_event_channel)
	,m_b_notification_armed(false)
	,m_n_sysvar_qp_compensation_level(safe_mce_sys().qp_compensation_level)
	,m_rx_lkey(g_buffer_pool_rx->find_lkey_by_ib_ctx_thread_safe(m_p_ib_ctx_handler))
	,m_b_sysvar_cq_keep_qp_full(safe_mce_sys().cq_keep_qp_full)
	,m_n_out_of_free_bufs_warning(0)
	,m_rx_buffs_rdy_for_free_head(NULL)
	,m_rx_buffs_rdy_for_free_tail(NULL)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_rx_lkey == 0) {
		__log_info_panic("invalid lkey found %u", m_rx_lkey);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	memset(&m_cq_stat_static, 0, sizeof(m_cq_stat_static));
	memset(&m_qp_rec, 0, sizeof(m_qp_rec));
	m_rx_queue.set_id("cq_mgr (%p) : m_rx_queue", this);
	m_rx_pool.set_id("cq_mgr (%p) : m_rx_pool", this);
	m_cq_id = atomic_fetch_and_inc(&m_n_cq_id_counter); // cq id is nonzero
	if (config)
		configure(cq_size);
}

void cq_mgr::configure(int cq_size)
{
	vma_ibv_cq_init_attr attr;
	memset(&attr, 0, sizeof(attr));

	prep_ibv_cq(attr);

	m_p_ibv_cq = vma_ibv_create_cq(m_p_ib_ctx_handler->get_ibv_context(),
			cq_size - 1, (void *)this, m_comp_event_channel, 0, &attr);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_ibv_cq) {
		throw_vma_exception("ibv_create_cq failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	VALGRIND_MAKE_MEM_DEFINED(m_p_ibv_cq, sizeof(ibv_cq));
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

	if (m_b_is_rx) {
		vma_stats_instance_create_cq_block(m_p_cq_stat);
	}
	
	if (m_b_is_rx) {
		m_b_is_rx_hw_csum_on = vma_is_rx_hw_csum_supported(m_p_ib_ctx_handler->get_ibv_device_attr());
		cq_logdbg("RX CSUM support = %d", m_b_is_rx_hw_csum_on);
	}

	cq_logdbg("Created CQ as %s with fd[%d] and of size %d elements (ibv_cq_hndl=%p)", (m_b_is_rx?"Rx":"Tx"), get_channel_fd(), cq_size, m_p_ibv_cq);
}

void cq_mgr::prep_ibv_cq(vma_ibv_cq_init_attr& attr) const
{
	if (m_p_ib_ctx_handler->get_ctx_time_converter_status()) {
		vma_ibv_cq_init_ts_attr(&attr);
	}
}

uint32_t cq_mgr::clean_cq()
{
	uint32_t ret_total = 0;
	int ret = 0;
	uint64_t cq_poll_sn = 0;
	mem_buf_desc_t* buff = NULL;
	/* coverity[stack_use_local_overflow] */
	vma_ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
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

	return ret_total;
}

cq_mgr::~cq_mgr()
{
	cq_logfunc("");
	cq_logdbg("destroying CQ as %s", (m_b_is_rx?"Rx":"Tx"));

	if (m_rx_buffs_rdy_for_free_head) {
		reclaim_recv_buffers(m_rx_buffs_rdy_for_free_head);
	}

	m_b_was_drained = true;
	if (m_rx_queue.size() + m_rx_pool.size()) {
		cq_logdbg("Returning %lu buffers to global Rx pool (ready queue %lu, free pool %lu))", m_rx_queue.size() + m_rx_pool.size(), m_rx_queue.size(), m_rx_pool.size());

		g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_queue, m_rx_queue.size());
		m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();

		g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_pool, m_rx_pool.size());
		m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
	}

	cq_logfunc("destroying ibv_cq");
	IF_VERBS_FAILURE_EX(ibv_destroy_cq(m_p_ibv_cq), EIO) {
		cq_logdbg("destroy cq failed (errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;
	VALGRIND_MAKE_MEM_UNDEFINED(m_p_ibv_cq, sizeof(ibv_cq));
	
	statistics_print();
	if (m_b_is_rx)
		vma_stats_instance_remove_cq_block(m_p_cq_stat);

	cq_logdbg("done");
}

void cq_mgr::statistics_print()
{
	if (m_p_cq_stat->n_rx_pkt_drop || m_p_cq_stat->n_rx_sw_queue_len || 
	    m_p_cq_stat->n_rx_drained_at_once_max || m_p_cq_stat->n_buffer_pool_len) {
		cq_logdbg_no_funcname("Packets dropped: %12llu", (unsigned long long int)m_p_cq_stat->n_rx_pkt_drop);
		cq_logdbg_no_funcname("Drained max: %17u",  m_p_cq_stat->n_rx_drained_at_once_max);
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
	descq_t temp_desc_list;
	temp_desc_list.set_id("cq_mgr (%p) : temp_desc_list", this);

	m_p_cq_stat->n_rx_drained_at_once_max = 0;

	/* return_extra_buffers(); */ //todo??

	// Initial fill of receiver work requests
	uint32_t qp_rx_wr_num = qp->get_rx_max_wr_num();
	cq_logdbg("Trying to push %d WRE to allocated qp (%p)", qp_rx_wr_num, qp);
	while (qp_rx_wr_num) {
		uint32_t n_num_mem_bufs = m_n_sysvar_rx_num_wr_to_post_recv;
		if (n_num_mem_bufs > qp_rx_wr_num)
			n_num_mem_bufs = qp_rx_wr_num;
		bool res = g_buffer_pool_rx->get_buffers_thread_safe(temp_desc_list, m_p_ring, n_num_mem_bufs, m_rx_lkey);
		if (!res) {
			VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_WARNING, VLOG_DEBUG, "WARNING Out of mem_buf_desc from Rx buffer pool for qp_mgr qp_mgr initialization (qp=%p),\n"
					"\tThis might happen due to wrong setting of VMA_RX_BUFS and VMA_RX_WRE. Please refer to README.txt for more info", qp);
			break;
		}

		qp->post_recv_buffers(&temp_desc_list, temp_desc_list.size());
		if (!temp_desc_list.empty()) {
			cq_logdbg("qp post recv is already full (push=%d, planned=%d)", qp->get_rx_max_wr_num()-qp_rx_wr_num, qp->get_rx_max_wr_num());
			g_buffer_pool_rx->put_buffers_thread_safe(&temp_desc_list, temp_desc_list.size());
			break;
		}
		qp_rx_wr_num -= n_num_mem_bufs;
	}
	cq_logdbg("Successfully post_recv qp with %d new Rx buffers (planned=%d)", qp->get_rx_max_wr_num()-qp_rx_wr_num, qp->get_rx_max_wr_num());

	// Add qp_mgr to map
	m_qp_rec.qp = qp;
	m_qp_rec.debt = 0;
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

	clean_cq();
	memset(&m_qp_rec, 0, sizeof(m_qp_rec));
}

void cq_mgr::add_qp_tx(qp_mgr* qp)
{
	//Assume locked!
	cq_logdbg("qp_mgr=%p", qp);
	m_qp_rec.qp = qp;
	m_qp_rec.debt = 0;
}

bool cq_mgr::request_more_buffers()
{
	cq_logfuncall("Allocating additional %d buffers for internal use", m_n_sysvar_qp_compensation_level);

	// Assume locked!
	// Add an additional free buffer descs to RX cq mgr
	bool res = g_buffer_pool_rx->get_buffers_thread_safe(m_rx_pool, m_p_ring, m_n_sysvar_qp_compensation_level, m_rx_lkey);
	if (!res) {
		cq_logfunc("Out of mem_buf_desc from RX free pool for internal object pool");
		return false;
	};

	m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
	return true;
}

void cq_mgr::return_extra_buffers()
{
	if (m_rx_pool.size() < m_n_sysvar_qp_compensation_level * 2)
		return;
	int buff_to_rel = m_rx_pool.size() - m_n_sysvar_qp_compensation_level;

	cq_logfunc("releasing %d buffers to global rx pool", buff_to_rel);
	g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_pool, buff_to_rel);
	m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
}

int cq_mgr::poll(vma_ibv_wc* p_wce, int num_entries, uint64_t* p_cq_poll_sn)
{
	// Assume locked!!!
	cq_logfuncall("");

#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_READY_POLL]);
#endif //RDTSC_MEASURE_RX_VERBS_READY_POLL

#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_IDLE_POLL]);
#endif //RDTSC_MEASURE_RX_VERBS_IDLE_POLL

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL]);
#endif //RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
	int ret = vma_ibv_poll_cq(m_p_ibv_cq, num_entries, p_wce);
	if (ret <= 0) {
#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
		RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_IDLE_POLL]);
#endif

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
		RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL]);
#endif
		// Zero polled wce    OR    ibv_poll_cq() has driver specific errors
		// so we can't really do anything with them
#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
		RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM]);
#endif
		*p_cq_poll_sn = m_n_global_sn;
#ifdef VMA_TIME_MEASURE
		INC_ERR_POLL_COUNT;
#endif
		return 0;
	}
	else {
#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_READY_POLL]);
#endif //RDTSC_MEASURE_RX_VERBS_READY_POLL

#ifdef RDTSC_MEASURE_RX_READY_POLL_TO_LWIP
		RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_READY_POLL_TO_LWIP]);
#endif
	}

#ifdef VMA_TIME_MEASURE
	TAKE_POLL_CQ_IN;
#endif

	if (unlikely(g_vlogger_level >= VLOG_FUNC_ALL)) {
		for (int i = 0; i < ret; i++) {
			cq_logfuncall("wce[%d] info wr_id=%x, status=%x, opcode=%x, vendor_err=%x, byte_len=%d, imm_data=%x", i, p_wce[i].wr_id, p_wce[i].status, vma_wc_opcode(p_wce[i]), p_wce[i].vendor_err, p_wce[i].byte_len, p_wce[i].imm_data);
			cq_logfuncall("qp_num=%x, src_qp=%x, wc_flags=%x, pkey_index=%x, slid=%x, sl=%x, dlid_path_bits=%x", p_wce[i].qp_num, p_wce[i].src_qp, vma_wc_flags(p_wce[i]), p_wce[i].pkey_index, p_wce[i].slid, p_wce[i].sl, p_wce[i].dlid_path_bits);
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

void cq_mgr::process_cq_element_log_helper(mem_buf_desc_t* p_mem_buf_desc, vma_ibv_wc* p_wce)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	// wce with bad status value
	if (p_wce->status == IBV_WC_SUCCESS) {
		cq_logdbg("wce: wr_id=%#lx, status=%#x, vendor_err=%#x, qp_num=%#x", p_wce->wr_id, p_wce->status, p_wce->vendor_err, p_wce->qp_num);
		if (m_b_is_rx_hw_csum_on && ! vma_wc_rx_hw_csum_ok(*p_wce))
			cq_logdbg("wce: bad rx_csum");
		cq_logdbg("wce: opcode=%#x, byte_len=%u, src_qp=%#x, wc_flags=%#lx", vma_wc_opcode(*p_wce), p_wce->byte_len, p_wce->src_qp, (unsigned long)vma_wc_flags(*p_wce));
		cq_logdbg("wce: pkey_index=%#x, slid=%#x, sl=%#x, dlid_path_bits=%#x, imm_data=%#x", p_wce->pkey_index, p_wce->slid, p_wce->sl, p_wce->dlid_path_bits, p_wce->imm_data);
		cq_logdbg("mem_buf_desc: lkey=%#x, p_buffer=%p, sz_buffer=%lu", p_mem_buf_desc->lkey, p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_buffer);
	} else if (p_wce->status != IBV_WC_WR_FLUSH_ERR) {
		cq_logwarn("wce: wr_id=%#lx, status=%#x, vendor_err=%#x, qp_num=%#x", p_wce->wr_id, p_wce->status, p_wce->vendor_err, p_wce->qp_num);
		cq_loginfo("wce: opcode=%#x, byte_len=%u, src_qp=%#x, wc_flags=%#lx", vma_wc_opcode(*p_wce), p_wce->byte_len, p_wce->src_qp, (unsigned long)vma_wc_flags(*p_wce));
		cq_loginfo("wce: pkey_index=%#x, slid=%#x, sl=%#x, dlid_path_bits=%#x, imm_data=%#x", p_wce->pkey_index, p_wce->slid, p_wce->sl, p_wce->dlid_path_bits, p_wce->imm_data);

		if (p_mem_buf_desc) {
			cq_logwarn("mem_buf_desc: lkey=%#x, p_buffer=%p, sz_buffer=%lu", p_mem_buf_desc->lkey, p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_buffer);
		}
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	cq_logfunc("wce error status '%s' [%d] (wr_id=%p, qp_num=%x)", priv_ibv_wc_status_str(p_wce->status), p_wce->status, p_wce->wr_id, p_wce->qp_num);
}

mem_buf_desc_t* cq_mgr::process_cq_element_tx(vma_ibv_wc* p_wce)
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
			m_p_ring->mem_buf_desc_completion_with_error_tx(p_mem_buf_desc);
		} else {
			// AlexR: can this wce have a valid mem_buf_desc pointer?
			// AlexR: are we throwing away a data buffer and a mem_buf_desc element?
			cq_logdbg("no desc_owner(wr_id=%lu, qp_num=%x)", p_wce->wr_id, p_wce->qp_num);
		}

		return NULL;
	}

	if (p_mem_buf_desc == NULL) {
		cq_logdbg("wce->wr_id = 0!!! When status == IBV_WC_SUCCESS");
		return NULL;
	}

	return p_mem_buf_desc;
}

mem_buf_desc_t* cq_mgr::process_cq_element_rx(vma_ibv_wc* p_wce)
{
	// Assume locked!!!
	cq_logfuncall("");

	// Get related mem_buf_desc pointer from the wr_id
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(uintptr_t)p_wce->wr_id;

	bool bad_wce = p_wce->status != IBV_WC_SUCCESS;

	if (unlikely(bad_wce || p_mem_buf_desc == NULL)) {
		if (p_mem_buf_desc == NULL) {
			m_p_next_rx_desc_poll = NULL;
			cq_logdbg("wce->wr_id = 0!!! When status == IBV_WC_SUCCESS");
			return NULL;
		}

		process_cq_element_log_helper(p_mem_buf_desc, p_wce);

		m_p_next_rx_desc_poll = NULL;

		if (p_mem_buf_desc == NULL) {
			cq_logdbg("wce->wr_id = 0!!! When status != IBV_WC_SUCCESS");
			return NULL;
		}
		if (p_mem_buf_desc->p_desc_owner) {
			m_p_ring->mem_buf_desc_completion_with_error_rx(p_mem_buf_desc);
			return NULL;
		}
		// AlexR: can this wce have a valid mem_buf_desc pointer?
		// AlexR: are we throwing away a data buffer and a mem_buf_desc element?
		cq_logdbg("no desc_owner(wr_id=%lu, qp_num=%x)", p_wce->wr_id, p_wce->qp_num);
		return NULL;
	}

	if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
		/*for debug:
		if (m_p_next_rx_desc_poll && m_p_next_rx_desc_poll != p_mem_buf_desc) {
			cq_logerr("prefetched wrong buffer");
		}*/
		m_p_next_rx_desc_poll = p_mem_buf_desc->p_prev_desc;
		p_mem_buf_desc->p_prev_desc = NULL;
	}

	p_mem_buf_desc->rx.is_sw_csum_need = !(m_b_is_rx_hw_csum_on && vma_wc_rx_hw_csum_ok(*p_wce));

	if (likely(vma_wc_opcode(*p_wce) & VMA_IBV_WC_RECV)) {
		// Save recevied total bytes
		p_mem_buf_desc->sz_data = p_wce->byte_len;

		//we use context to verify that on reclaim rx buffer path we return the buffer to the right CQ
		p_mem_buf_desc->rx.is_vma_thr = false;
		p_mem_buf_desc->rx.context = this;
		p_mem_buf_desc->rx.socketxtreme_polled = false;

		//this is not a deadcode if timestamping is defined in verbs API
		// coverity[dead_error_condition]
		if (vma_wc_flags(*p_wce) & VMA_IBV_WC_WITH_TIMESTAMP) {
			p_mem_buf_desc->rx.hw_raw_timestamp = vma_wc_timestamp(*p_wce);
		}

		VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

		prefetch_range((uint8_t*)p_mem_buf_desc->p_buffer + m_sz_transport_header, 
				std::min(p_mem_buf_desc->sz_data - m_sz_transport_header, (size_t)m_n_sysvar_rx_prefetch_bytes));
		//prefetch((uint8_t*)p_mem_buf_desc->p_buffer + m_sz_transport_header);
	}

	return p_mem_buf_desc;
}

bool cq_mgr::compensate_qp_poll_success(mem_buf_desc_t* buff_cur)
{
	// Assume locked!!!
	// Compensate QP for all completions that we found
	if (m_rx_pool.size() || request_more_buffers()) {
		size_t buffers = std::min<size_t>(m_qp_rec.debt, m_rx_pool.size());
		m_qp_rec.qp->post_recv_buffers(&m_rx_pool, buffers);
		m_qp_rec.debt -= buffers;
		m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
	}
	else if (m_b_sysvar_cq_keep_qp_full ||
			m_qp_rec.debt + MCE_MAX_CQ_POLL_BATCH > (int)m_qp_rec.qp->m_rx_num_wr) {
		m_p_cq_stat->n_rx_pkt_drop++;
		m_qp_rec.qp->post_recv_buffer(buff_cur);
		--m_qp_rec.debt;
		return true;
	}

	return false;
}

void cq_mgr::compensate_qp_poll_failed()
{
	// Assume locked!!!
	// Compensate QP for all completions debt
	if (m_qp_rec.debt) {
		if (likely(m_rx_pool.size() || request_more_buffers())) {
			size_t buffers = std::min<size_t>(m_qp_rec.debt, m_rx_pool.size());
			m_qp_rec.qp->post_recv_buffers(&m_rx_pool, buffers);
			m_qp_rec.debt -= buffers;
			m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
		}
	}
}

void cq_mgr::reclaim_recv_buffer_helper(mem_buf_desc_t* buff)
{
	if (buff->dec_ref_count() <= 1 && (buff->lwip_pbuf.pbuf.ref-- <= 1)) {
		if (likely(buff->p_desc_owner == m_p_ring)) {
			mem_buf_desc_t* temp = NULL;
			while (buff) {
				VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER;
				temp = buff;
				buff = temp->p_next_desc;
				temp->p_next_desc = NULL;
				temp->p_prev_desc = NULL;
				temp->reset_ref_count();
				temp->rx.tcp.gro = 0;
				temp->rx.is_vma_thr = false;
				temp->rx.socketxtreme_polled = false;
				temp->rx.flow_tag_id = 0;
				temp->rx.tcp.p_ip_h = NULL;
				temp->rx.tcp.p_tcp_h = NULL;
				temp->rx.timestamps.sw.tv_nsec = 0;
				temp->rx.timestamps.sw.tv_sec = 0;
				temp->rx.timestamps.hw.tv_nsec = 0;
				temp->rx.timestamps.hw.tv_sec = 0;
				temp->rx.hw_raw_timestamp = 0;
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

void cq_mgr::process_tx_buffer_list(mem_buf_desc_t* p_mem_buf_desc)
{
	// Assume locked!!!
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_mem_buf_desc && (p_mem_buf_desc->p_desc_owner == m_p_ring /*|| m_p_ring->get_parent()->is_member(p_mem_buf_desc->p_desc_owner)*/)) {
		m_p_ring->mem_buf_desc_return_to_owner_tx(p_mem_buf_desc);
		/* if decided to free buffers of another ring here, need to modify return_to_owner to check owner and return to gpool. */
	}
	else if (p_mem_buf_desc && m_p_ring->get_parent()->is_member(p_mem_buf_desc->p_desc_owner)) {
		cq_logerr("got buffer of wrong owner, high-availability event? buf=%p, owner=%p", p_mem_buf_desc, p_mem_buf_desc ? p_mem_buf_desc->p_desc_owner : NULL);
		/* if decided to free buffers here, remember its a list and need to deref members. */
		//p_mem_buf_desc->p_desc_owner->mem_buf_desc_return_to_owner_tx(p_mem_buf_desc); /* this can cause a deadlock between rings, use trylock? */
	} else {
		cq_logerr("got buffer of wrong owner, buf=%p, owner=%p", p_mem_buf_desc, p_mem_buf_desc ? p_mem_buf_desc->p_desc_owner : NULL);
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

int cq_mgr::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	// Assume locked!!!
	cq_logfuncall("");

	/* coverity[stack_use_local_overflow] */
	vma_ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];

	int ret;
	uint32_t ret_rx_processed = process_recv_queue(pv_fd_ready_array);
	if (unlikely(ret_rx_processed >= m_n_sysvar_cq_poll_batch_max)) {
		m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
		return ret_rx_processed;
	}

	if (m_p_next_rx_desc_poll) {
		prefetch_range((uint8_t*)m_p_next_rx_desc_poll->p_buffer, m_n_sysvar_rx_prefetch_bytes_before_poll);
	}

	ret = poll(wce, m_n_sysvar_cq_poll_batch_max, p_cq_poll_sn);
	if (ret > 0) {
		m_n_wce_counter += ret;
		if (ret < (int)m_n_sysvar_cq_poll_batch_max)
			m_b_was_drained = true;

		for (int i = 0; i < ret; i++) {
			mem_buf_desc_t *buff = process_cq_element_rx((&wce[i]));
			if (buff) {
				if (vma_wc_opcode(wce[i]) & VMA_IBV_WC_RECV) {
					if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
							!compensate_qp_poll_success(buff)) {
						process_recv_buffer(buff, pv_fd_ready_array);
					}
				}
			}
		}
		ret_rx_processed += ret;
		m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
	} else {
		compensate_qp_poll_failed();
	}
	
	return ret_rx_processed;
}

int cq_mgr::poll_and_process_element_tx(uint64_t* p_cq_poll_sn)
{
	// Assume locked!!!
	cq_logfuncall("");
	
	/* coverity[stack_use_local_overflow] */
	vma_ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
	int ret = poll(wce, m_n_sysvar_cq_poll_batch_max, p_cq_poll_sn);
	if (ret > 0) {
		m_n_wce_counter += ret;
		if (ret < (int)m_n_sysvar_cq_poll_batch_max)
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

int cq_mgr::poll_and_process_element_rx(mem_buf_desc_t **p_desc_lst)
{
	NOT_IN_USE(p_desc_lst);
	cq_logerr("SocketXtreme mode is supported by mlx5 cq manager only");
	return 0;
}

bool cq_mgr::reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst)
{
	if (m_rx_buffs_rdy_for_free_head) {
		reclaim_recv_buffer_helper(m_rx_buffs_rdy_for_free_head);
		m_rx_buffs_rdy_for_free_head = m_rx_buffs_rdy_for_free_tail = NULL;
	}
	reclaim_recv_buffer_helper(rx_reuse_lst);
	return_extra_buffers();

	return true;
}

bool cq_mgr::reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst)
{
	if (likely(rx_reuse_lst)) {
		reclaim_recv_buffer_helper(rx_reuse_lst);
		return true;
	}
	return false;
}

int cq_mgr::reclaim_recv_single_buffer(mem_buf_desc_t* rx_reuse)
{
	int ret_val = 0;

	ret_val = rx_reuse->lwip_pbuf_dec_ref_count();
	if ((ret_val == 0) && (rx_reuse->get_ref_count() <= 0)) {
 		/*if ((safe_mce_sys().thread_mode > THREAD_MODE_SINGLE)) {
		 m_lock_ring_rx.lock();
		}*/
 		if (!m_rx_buffs_rdy_for_free_head) {
 			m_rx_buffs_rdy_for_free_head = m_rx_buffs_rdy_for_free_tail = rx_reuse;
 		}
 		else {
			m_rx_buffs_rdy_for_free_tail->p_next_desc = rx_reuse;
			m_rx_buffs_rdy_for_free_tail = rx_reuse;
		}
 		m_rx_buffs_rdy_for_free_tail->p_next_desc = NULL;
		/*if ((safe_mce_sys().thread_mode > THREAD_MODE_SINGLE)) {
			m_lock_ring_rx.lock();
		}*/
	}
	return ret_val;
}

bool cq_mgr::reclaim_recv_buffers(descq_t *rx_reuse)
{
	cq_logfuncall("");
	// Called from outside cq_mgr context which is not locked!!
	while (!rx_reuse->empty()) {
		mem_buf_desc_t* buff = rx_reuse->get_and_pop_front();
		reclaim_recv_buffer_helper(buff);
	}
	return_extra_buffers();

	return true;
}

//
// @OUT: p_recycle_buffers_last_wr_id	Returns the final WR_ID handled. When set, this indicates this is a CQE drain flow.
// @OUT:				returns total number of processes CQE's
//


int cq_mgr::drain_and_proccess(uintptr_t* p_recycle_buffers_last_wr_id /*=NULL*/)
{
	cq_logfuncall("cq was %s drained. %d processed wce since last check. %d wce in m_rx_queue", (m_b_was_drained?"":"not "), m_n_wce_counter, m_rx_queue.size());

	// CQ polling loop until max wce limit is reached for this interval or CQ is drained
	uint32_t ret_total = 0;
	uint64_t cq_poll_sn = 0;

	/* drain_and_proccess() is mainly called in following cases as
	 * Internal thread:
	 *   Frequency of real polling can be controlled by
	 *   VMA_PROGRESS_ENGINE_INTERVAL and VMA_PROGRESS_ENGINE_WCE_MAX.
	 * socketxtreme:
	 *   User does socketxtreme_poll()
	 * Cleanup:
	 *   QP down logic to release rx buffers should force polling to do this.
	 *   Not null argument indicates one.
	 */
	while (((m_n_sysvar_progress_engine_wce_max > m_n_wce_counter) && (!m_b_was_drained)) ||
		(p_recycle_buffers_last_wr_id)) {

		/* coverity[stack_use_local_overflow] */
		vma_ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
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
				if (p_recycle_buffers_last_wr_id) {
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
						buff->rx.is_vma_thr = true;
						if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
								!compensate_qp_poll_success(buff)) {
							process_recv_buffer(buff, NULL);
						}
					}
					else { //udp/ip traffic we just put in the cq's rx queue
						m_rx_queue.push_back(buff);
						mem_buf_desc_t* buff_cur = m_rx_queue.get_and_pop_front();
						if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
								!compensate_qp_poll_success(buff_cur)) {
							m_rx_queue.push_front(buff_cur);
						}
					}
				}
			}
			if (p_recycle_buffers_last_wr_id) {
				*p_recycle_buffers_last_wr_id = (uintptr_t)wce[i].wr_id;
			}
		}
		ret_total += ret;
	}
	m_p_ring->m_gro_mgr.flush_all(NULL);

	m_n_wce_counter = 0;
	m_b_was_drained = false;

	// Update cq statistics
	m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
	m_p_cq_stat->n_rx_drained_at_once_max = std::max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

	return ret_total;
}

//  1 -> busy
//  0 -> ok
// -1 -> error
int cq_mgr::ack_and_request_notification()
{
	int res, cq_ev_count = 0;
	ibv_cq* ib_cq;
	void *cq_context;
	do {
		res = ibv_get_cq_event(m_comp_event_channel, &ib_cq, &cq_context);
		if (res == 0) {
			++cq_ev_count;
		}
	} while (res == 0);
	if (errno != EAGAIN) {
		return -1;
	}
	if (cq_ev_count > 0) {
		get_cq_event(cq_ev_count);
		ibv_ack_cq_events(m_p_ibv_cq, cq_ev_count);
		return 1;
	}
	IF_VERBS_FAILURE(req_notify_cq()) {
		cq_logerr("Failure arming the qp_mgr notification channel (errno=%d %m)", errno);
		return -1;
	}
	ENDIF_VERBS_FAILURE
	return 0;
}

int cq_mgr::request_notification(uint64_t poll_sn)
{
	int ret = -1;

	cq_logfuncall("");

	if ((m_n_global_sn > 0 && poll_sn != m_n_global_sn)) {
		// The cq_mgr's has receive packets pending processing (or got processed since cq_poll_sn)
		cq_logfunc("miss matched poll sn (user=0x%lx, cq=0x%lx)", poll_sn, m_n_cq_poll_sn);
		return 1;
	}

	if (m_b_notification_armed == false) {

		cq_logfunc("arming cq_mgr notification channel");

		// Arm the CQ notification channel
		IF_VERBS_FAILURE(req_notify_cq()) {
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
	int ret = -1;

	cq_logfunc("");

	if (m_b_notification_armed) {
		cq_mgr* p_cq_mgr_context = NULL;
		struct ibv_cq* p_cq_hndl = NULL;
		void *p; // deal with compiler warnings

		// Block on the cq_mgr's notification event channel
		IF_VERBS_FAILURE(ibv_get_cq_event(m_comp_event_channel, &p_cq_hndl, &p)) {
			cq_logfunc("waiting on cq_mgr event returned with error (errno=%d %m)", errno);
		}
		else {
			get_cq_event();
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
				ret = poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array);
			} else {
				ret = poll_and_process_element_tx(p_cq_poll_sn);
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
		p_cq_mgr->get_cq_event();
		ibv_ack_cq_events(p_cq_hndl, 1); // Ack the ibv event
	} ENDIF_VERBS_FAILURE;

	return p_cq_mgr;
}
