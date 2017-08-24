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

#include "cq_mgr_mlx5.h"

#ifdef HAVE_INFINIBAND_MLX5_HW_H

#include <infiniband/mlx5_hw.h>
#include <vma/util/valgrind.h>
#include "cq_mgr.inl"
#include "cq_mgr_mlx5.inl"
#include "qp_mgr.h"
#include "qp_mgr_eth_mlx5.h"
#include "ring_simple.h"
#include "vma/util/instrumentation.h"

#define MODULE_NAME "cqm_mlx5"

#define cq_logfunc     __log_info_func
#define cq_logdbg      __log_info_dbg
#define cq_logerr      __log_info_err
#define cq_logfuncall  __log_info_funcall


cq_mgr_mlx5::cq_mgr_mlx5(ring_simple* p_ring, ib_ctx_handler* p_ib_ctx_handler,
			 uint32_t cq_size, struct ibv_comp_channel* p_comp_event_channel,
			 bool is_rx, bool call_configure):
	cq_mgr(p_ring, p_ib_ctx_handler, cq_size, p_comp_event_channel, is_rx, call_configure)
	,m_cq_size(cq_size)
	,m_cq_cons_index(0)
	,m_cqes(NULL)
	,m_cq_dbell(NULL)
	,m_rq(NULL)
	,m_rx_hot_buffer(NULL)
	,m_p_rq_wqe_idx_to_wrid(NULL)
	,m_qp(NULL)
{
	cq_logfunc("");
}

uint32_t cq_mgr_mlx5::clean_cq()
{
	uint32_t ret_total = 0;
	uint64_t cq_poll_sn = 0;
	mem_buf_desc_t* buff;

	if (m_b_is_rx) {
		if (m_rq) {
			buff_status_e status = BS_OK;
			while((buff = poll(status))) {
				if (process_cq_element_rx( buff, status)) {
					m_rx_queue.push_back(buff);
				}
				++ret_total;
			}
			update_global_sn(cq_poll_sn, ret_total);
		}
	} else {//Tx
		int ret = 0;
		/* coverity[stack_use_local_overflow] */
		vma_ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
		while ((ret = cq_mgr::poll(wce, MCE_MAX_CQ_POLL_BATCH, &cq_poll_sn)) > 0) {
			for (int i = 0; i < ret; i++) {
				buff = process_cq_element_tx(&wce[i]);
				if (buff)
					m_rx_queue.push_back(buff);
			}
			ret_total += ret;
		}
	}

	return ret_total;
}

cq_mgr_mlx5::~cq_mgr_mlx5()
{
	cq_logfunc("");
	cq_logdbg("destroying CQ as %s", (m_b_is_rx?"Rx":"Tx"));
	m_rq = NULL;
}

mem_buf_desc_t* cq_mgr_mlx5::poll(enum buff_status_e& status)
{
	mem_buf_desc_t *buff = NULL;

	RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL_END;
	RDTSC_MEASURE_RX_VERBS_READY_OR_IDLE_POLL_START;

	if (unlikely(NULL == m_rx_hot_buffer)) {
		if (likely(m_rq->tail != m_rq->head)) {
			uint32_t index = m_rq->tail & (m_qp_rec.qp->m_rx_num_wr - 1);
			m_rx_hot_buffer = (mem_buf_desc_t *)m_p_rq_wqe_idx_to_wrid[index];
			m_p_rq_wqe_idx_to_wrid[index] = 0;
			prefetch((void*)m_rx_hot_buffer);
			prefetch((void*)&(*m_cqes)[m_cq_cons_index & (m_cq_size - 1)]);
		} else {
			RDTSC_FLOW_RX_VERBS_IDLE_POLL_END;
			RDTSC_MEASURE_RX_VERBS_READY_OR_IDLE_POLL_START;
			/* If rq_tail and rq_head are pointing to the same wqe,
			 * the wq is empty and there is no cqe to be received */
			return NULL;
		}
	}
	volatile mlx5_cqe64 *cqe = check_cqe();
	if (likely(cqe)) {
		/* Update the consumer index */
		++m_cq_cons_index;
		wmb();
		cqe64_to_mem_buff_desc(cqe, m_rx_hot_buffer, status);
		++m_rq->tail;
		*m_cq_dbell = htonl(m_cq_cons_index & 0xffffff);
		buff = m_rx_hot_buffer;
		m_rx_hot_buffer = NULL;

		RDTSC_FLOW_RX_VERBS_READY_POLL_END;
		RDTSC_FLOW_RX_READY_POLL_TO_LWIP_START;
	} else {
		RDTSC_FLOW_RX_VERBS_IDLE_POLL_END;
		RDTSC_MEASURE_RX_VERBS_READY_OR_IDLE_POLL_START;
		prefetch((void*)m_rx_hot_buffer);
	}

	prefetch((void*)&(*m_cqes)[m_cq_cons_index & (m_cq_size - 1)]);

	return buff;
}

inline void cq_mgr_mlx5::cqe64_to_mem_buff_desc(volatile struct mlx5_cqe64 *cqe, mem_buf_desc_t* p_rx_wc_buf_desc, enum buff_status_e &status)
{
	struct mlx5_err_cqe *ecqe;
	ecqe = (struct mlx5_err_cqe *)cqe;

	switch (MLX5_CQE_OPCODE(cqe->op_own)) {
		case MLX5_CQE_RESP_WR_IMM:
			cq_logerr("IBV_WC_RECV_RDMA_WITH_IMM is not supported");
			status = BS_CQE_RESP_WR_IMM_NOT_SUPPORTED;
			break;
		case MLX5_CQE_RESP_SEND:
		case MLX5_CQE_RESP_SEND_IMM:
		case MLX5_CQE_RESP_SEND_INV:
		{
			status = BS_OK;
			p_rx_wc_buf_desc->rx.hw_raw_timestamp = ntohll(cqe->timestamp);
			p_rx_wc_buf_desc->rx.flow_tag_id      = vma_get_flow_tag(cqe);

#ifdef DEFINED_MLX5_HW_ETH_WQE_HEADER
			p_rx_wc_buf_desc->rx.is_sw_csum_need = !(m_b_is_rx_hw_csum_on && (cqe->hds_ip_ext & MLX5_CQE_L4_OK) && (cqe->hds_ip_ext & MLX5_CQE_L3_OK));
#else
			p_rx_wc_buf_desc->rx.is_sw_csum_need = !m_b_is_rx_hw_csum_on; /* we assume that the checksum is ok */
#endif
			p_rx_wc_buf_desc->sz_data = ntohl(cqe->byte_cnt);
			return;
		}
		case MLX5_CQE_INVALID: /* No cqe!*/
		{
			cq_logerr("We should no receive a buffer without a cqe\n");
			status = BS_CQE_INVALID;
			break;
		}
		case MLX5_CQE_REQ:
		case MLX5_CQE_SIG_ERR:
		case MLX5_CQE_REQ_ERR:
		case MLX5_CQE_RESP_ERR:
		default:
		{
			if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR == ecqe->syndrome) {
				status = BS_IBV_WC_WR_FLUSH_ERR;
			} else {
				status = BS_GENERAL_ERR;
			}
			/*
			  IB compliant completion with error syndrome:
			  0x1: Local_Length_Error
			  0x2: Local_QP_Operation_Error
			  0x4: Local_Protection_Error
			  0x5: Work_Request_Flushed_Error
			  0x6: Memory_Window_Bind_Error
			  0x10: Bad_Response_Error
			  0x11: Local_Access_Error
			  0x12: Remote_Invalid_Request_Error
			  0x13: Remote_Access_Error
			  0x14: Remote_Operation_Error
			  0x15: Transport_Retry_Counter_Exceeded
			  0x16: RNR_Retry_Counter_Exceeded
			  0x22: Aborted_Error
			  other: Reserved
			 */
			break;
		}
	}
}

int cq_mgr_mlx5::drain_and_proccess(uintptr_t* p_recycle_buffers_last_wr_id /*=NULL*/)
{
	cq_logfuncall("cq was %sdrained. %d processed wce since last check. %d wce in m_rx_queue", (m_b_was_drained?"":"not "), m_n_wce_counter, m_rx_queue.size());

	/* CQ polling loop until max wce limit is reached for this interval or CQ is drained */
	uint32_t ret_total = 0;
	uint64_t cq_poll_sn = 0;

	if (p_recycle_buffers_last_wr_id != NULL) {
		m_b_was_drained = false;
	}

	while ((m_n_sysvar_progress_engine_wce_max > m_n_wce_counter) &&
		!m_b_was_drained) {
		buff_status_e status = BS_OK;
		mem_buf_desc_t* buff = poll(status);
		if (NULL == buff) {
			update_global_sn(cq_poll_sn, ret_total);
			m_b_was_drained = true;
			m_p_ring->m_gro_mgr.flush_all(NULL);
			return ret_total;
		}

		++m_n_wce_counter;

		if (process_cq_element_rx(buff, status)) {
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
				/* We process immediately all non udp/ip traffic.. */
				if (procces_now) {
					buff->rx.is_vma_thr = true;
					if (!compensate_qp_poll_success(buff)) {
						process_recv_buffer(buff, NULL);
					}
				}
				else { /* udp/ip traffic we just put in the cq's rx queue */
					m_rx_queue.push_back(buff);
					mem_buf_desc_t* buff_cur = m_rx_queue.front();
					m_rx_queue.pop_front();
					if (!compensate_qp_poll_success(buff_cur)) {
						m_rx_queue.push_front(buff_cur);
					}
				}
			}
		}

		if (p_recycle_buffers_last_wr_id) {
			*p_recycle_buffers_last_wr_id = (uintptr_t)buff;
		}

		++ret_total;
	}

	update_global_sn(cq_poll_sn, ret_total);

	m_p_ring->m_gro_mgr.flush_all(NULL);

	m_n_wce_counter = 0;
	m_b_was_drained = false;

	/* Update cq statistics */
	m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
	m_p_cq_stat->n_rx_drained_at_once_max = max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

	return ret_total;
}

inline void cq_mgr_mlx5::update_global_sn(uint64_t& cq_poll_sn, uint32_t num_polled_cqes)
{
	if (num_polled_cqes > 0) {
		// spoil the global sn if we have packets ready
		union __attribute__((packed)) {
			uint64_t global_sn;
			struct {
				uint32_t cq_id;
				uint32_t cq_sn;
			} bundle;
		} next_sn;
		m_n_cq_poll_sn += num_polled_cqes;
		next_sn.bundle.cq_sn = m_n_cq_poll_sn;
		next_sn.bundle.cq_id = m_cq_id;

		m_n_global_sn = next_sn.global_sn;
	}

	cq_poll_sn = m_n_global_sn;
}

mem_buf_desc_t* cq_mgr_mlx5::process_cq_element_rx(mem_buf_desc_t* p_mem_buf_desc, enum buff_status_e status)
{
	/* Assume locked!!! */
	cq_logfuncall("");

	/* we use context to verify that on reclaim rx buffer path we return the buffer to the right CQ */
	p_mem_buf_desc->rx.is_vma_thr = false;
	p_mem_buf_desc->rx.context = this;

	if (unlikely((status != BS_OK) ||
			     (m_b_is_rx_hw_csum_on && p_mem_buf_desc->rx.is_sw_csum_need))) {
		m_p_next_rx_desc_poll = NULL;
		if (p_mem_buf_desc->p_desc_owner) {
			p_mem_buf_desc->p_desc_owner->mem_buf_desc_completion_with_error_rx(p_mem_buf_desc);
		} else {
			/* AlexR: are we throwing away a data buffer and a mem_buf_desc element? */
			cq_logdbg("no desc_owner(wr_id=%p)", p_mem_buf_desc);
		}

		return NULL;
	}

	if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
		m_p_next_rx_desc_poll = p_mem_buf_desc->p_prev_desc;
		p_mem_buf_desc->p_prev_desc = NULL;
	}

	VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

	prefetch_range((uint8_t*)p_mem_buf_desc->p_buffer + m_sz_transport_header,
	min(p_mem_buf_desc->sz_data - m_sz_transport_header, (size_t)m_n_sysvar_rx_prefetch_bytes));


	return p_mem_buf_desc;
}

int cq_mgr_mlx5::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	/* Assume locked!!! */
	cq_logfuncall("");

	uint32_t ret_rx_processed = process_recv_queue(pv_fd_ready_array);
	if (unlikely(ret_rx_processed >= m_n_sysvar_cq_poll_batch_max)) {
		m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
		return ret_rx_processed;
	}

	if (m_p_next_rx_desc_poll) {
		prefetch_range((uint8_t*)m_p_next_rx_desc_poll->p_buffer, m_n_sysvar_rx_prefetch_bytes_before_poll);
	}

	buff_status_e status = BS_OK;
	uint32_t ret = 0;
	while (ret < m_n_sysvar_cq_poll_batch_max) {
		mem_buf_desc_t *buff = poll(status);
		if (buff) {
			++ret;
			if (process_cq_element_rx(buff, status)) {
				if (!compensate_qp_poll_success(buff)) {
					process_recv_buffer(buff, pv_fd_ready_array);
				}
			}
		} else {
			m_b_was_drained = true;
			break;
		}
	}

	update_global_sn(*p_cq_poll_sn, ret);

	if (likely(ret > 0)) {
		ret_rx_processed += ret;
		m_n_wce_counter += ret;
		m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
	} else {
		compensate_qp_poll_failed();
	}

	return ret_rx_processed;
}

inline void cq_mgr_mlx5::cqe64_to_vma_wc(volatile struct mlx5_cqe64 *cqe, vma_ibv_wc *wc)
{
	struct mlx5_err_cqe* ecqe = (struct mlx5_err_cqe *)cqe;

	switch (cqe->op_own >> 4) {
	case MLX5_CQE_RESP_WR_IMM:
		cq_logerr("IBV_WC_RECV_RDMA_WITH_IMM is not supported");
		break;
	case MLX5_CQE_RESP_SEND:
	case MLX5_CQE_RESP_SEND_IMM:
	case MLX5_CQE_RESP_SEND_INV:
		vma_wc_opcode(*wc) = VMA_IBV_WC_RECV;
		wc->byte_len = ntohl(cqe->byte_cnt);
		wc->status = IBV_WC_SUCCESS;
		return;
	case MLX5_CQE_REQ:
		wc->status = IBV_WC_SUCCESS;
		return;
	default:
		break;
	}

	/* Only IBV_WC_WR_FLUSH_ERR is used in code */
	if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR == ecqe->syndrome) {
		wc->status = IBV_WC_WR_FLUSH_ERR;
	} else {
		wc->status = IBV_WC_GENERAL_ERR;
	}

	wc->vendor_err = ecqe->vendor_err_synd;
}

inline volatile struct mlx5_cqe64* cq_mgr_mlx5::check_error_completion(volatile struct mlx5_cqe64 *cqe,
								 volatile uint32_t *ci, uint8_t op_own)
{
	switch (op_own >> 4) {
	case MLX5_CQE_REQ_ERR:
	case MLX5_CQE_RESP_ERR:
		++(*ci);
		wmb();
		*m_cq_dbell = htonl(m_cq_cons_index);
		return cqe;

	case MLX5_CQE_INVALID:
	default:
		return NULL; /* No CQE */
	}
}

inline volatile struct mlx5_cqe64 *cq_mgr_mlx5::get_cqe64(volatile struct mlx5_cqe64 **cqe_err)
{

	volatile struct mlx5_cqe64 *cqe= &(*m_cqes)[m_cq_cons_index & (m_cq_size - 1)];
	uint8_t op_own = cqe->op_own;

	*cqe_err = NULL;
	if (unlikely((op_own & MLX5_CQE_OWNER_MASK) == !(m_cq_cons_index & m_cq_size))) {
		return NULL;
	} else if (unlikely(op_own & 0x80)) {
		*cqe_err = check_error_completion(cqe, &m_cq_cons_index, op_own);
		return NULL;
	}

	++m_cq_cons_index;
	wmb();
	*m_cq_dbell = htonl(m_cq_cons_index);

	return cqe;
}

int cq_mgr_mlx5::poll_and_process_error_element_tx(volatile struct mlx5_cqe64 *cqe, uint64_t* p_cq_poll_sn)
{
	uint16_t wqe_ctr = ntohs(cqe->wqe_counter);
	int index = wqe_ctr & (m_qp->m_tx_num_wr - 1);
	mem_buf_desc_t* buff = NULL;
	vma_ibv_wc wce;

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

	memset(&wce, 0, sizeof(wce));
	if (m_qp->m_sq_wqe_idx_to_wrid) {
		wce.wr_id = m_qp->m_sq_wqe_idx_to_wrid[index];
		cqe64_to_vma_wc(cqe, &wce);

		buff = cq_mgr::process_cq_element_tx(&wce);
		if (buff) {
			cq_mgr::process_tx_buffer_list(buff);
		}
		return 1;
	}
	return 0;
}

int cq_mgr_mlx5::poll_and_process_element_tx(uint64_t* p_cq_poll_sn)
{
	// Assume locked!!!
	cq_logfuncall("");

	int ret = 0;
	volatile mlx5_cqe64 *cqe_err = NULL;
	volatile mlx5_cqe64 *cqe = get_cqe64(&cqe_err);

	if (likely(cqe)) {
		uint16_t wqe_ctr = ntohs(cqe->wqe_counter);
		int index = wqe_ctr & (m_qp->m_tx_num_wr - 1);
		mem_buf_desc_t* buff = (mem_buf_desc_t*)(uintptr_t)m_qp->m_sq_wqe_idx_to_wrid[index];
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

		cq_mgr::process_tx_buffer_list(buff);
		ret = 1;
	}
	else if (cqe_err) {
		ret = poll_and_process_error_element_tx(cqe_err, p_cq_poll_sn);
	}
	else {
		*p_cq_poll_sn = m_n_global_sn;
	}

	return ret;
}

void cq_mgr_mlx5::set_qp_rq(qp_mgr* qp)
{
	struct ibv_cq *ibcq = m_p_ibv_cq; // ibcp is used in next macro: _to_mxxx
	struct mlx5_cq *mlx5_cq = _to_mxxx(cq, cq);
	struct verbs_qp *vqp = (struct verbs_qp *)qp->m_qp;
	struct mlx5_qp * mlx5_hw_qp = (struct mlx5_qp*)container_of(vqp, struct mlx5_qp, verbs_qp);

	m_rq = &(mlx5_hw_qp->rq);
	m_p_rq_wqe_idx_to_wrid = qp->m_rq_wqe_idx_to_wrid;
	qp->m_rq_wqe_counter = 0; /* In case of bonded qp, wqe_counter must be reset to zero */
	m_rx_hot_buffer = NULL;
	m_cq_dbell = mlx5_cq->dbrec;
	m_cqes = (struct mlx5_cqe64 (*)[])(uintptr_t)mlx5_cq->active_buf->buf;
}

void cq_mgr_mlx5::add_qp_rx(qp_mgr* qp)
{
	cq_logfunc("");
	set_qp_rq(qp);
	cq_mgr::add_qp_rx(qp);
}

void cq_mgr_mlx5::del_qp_rx(qp_mgr *qp)
{
	cq_mgr::del_qp_rx(qp);
	m_p_rq_wqe_idx_to_wrid = NULL;
}

inline void cq_mgr_mlx5::update_consumer_index()
{
	struct ibv_cq *ibcq = m_p_ibv_cq; // ibcp is used in next macro: _to_mxxx
	struct mlx5_cq* mlx5_cq = _to_mxxx(cq, cq);
	mlx5_cq->cons_index = m_cq_cons_index;
	wmb();
}

int cq_mgr_mlx5::request_notification(uint64_t poll_sn)
{
	update_consumer_index();
	return cq_mgr::request_notification(poll_sn);
}

int cq_mgr_mlx5::wait_for_notification_and_process_element(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array/* = NULL*/)
{
	update_consumer_index();
	return cq_mgr::wait_for_notification_and_process_element(p_cq_poll_sn, pv_fd_ready_array);
}

void cq_mgr_mlx5::add_qp_tx(qp_mgr* qp)
{
	//Assume locked!
	cq_mgr::add_qp_tx(qp);
	struct ibv_cq *ibcq = m_p_ibv_cq; // ibcp is used in next macro: _to_mxxx
	struct mlx5_cq *mlx5_cq = _to_mxxx(cq, cq);
	m_qp = static_cast<qp_mgr_eth_mlx5*> (qp);
	m_cq_dbell = mlx5_cq->dbrec;
	m_cqes = (struct mlx5_cqe64 (*)[])(uintptr_t)mlx5_cq->active_buf->buf;
	cq_logfunc("qp_mgr=%p m_cq_dbell=%p m_cqes=%p", m_qp, m_cq_dbell, m_cqes);
}

#endif//HAVE_INFINIBAND_MLX5_HW_H
