/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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
#include "qp_mgr_eth_direct.h"
#include "vlogger/vlogger.h"
#include "vma/util/valgrind.h"
#include "cq_mgr_mlx5.h"
#include "ring_simple.h"

#if defined(DEFINED_DIRECT_VERBS)

#undef  MODULE_NAME
#define MODULE_NAME 	"qp_mgr_direct"
#define qp_logpanic 	__log_info_panic
#define qp_logerr	__log_info_err
#define qp_logwarn	__log_info_warn
#define qp_loginfo	__log_info_info
#define qp_logdbg	__log_info_dbg
#define qp_logfunc	__log_info_func
#define qp_logfuncall	__log_info_funcall

qp_mgr_eth_direct::qp_mgr_eth_direct(const ring_simple* p_ring,
		const ib_ctx_handler* p_context, const uint8_t port_num,
		ibv_comp_channel* p_rx_comp_event_channel,
		const uint32_t tx_num_wr, const uint16_t vlan):
			qp_mgr_eth_mlx5(p_ring, p_context, port_num,
				p_rx_comp_event_channel, tx_num_wr, vlan, false)
{
	// must be called from this class to call derived prepare_ibv_qp
	if (configure(p_rx_comp_event_channel)) {
		throw_vma_exception("failed creating qp_mgr_eth");
	}

	qp_logfunc("m_p_qp= %p", m_qp);
}

cq_mgr* qp_mgr_eth_direct::init_tx_cq_mgr()
{
	m_tx_num_wr = m_p_ib_ctx_handler->get_ibv_device_attr()->max_qp_wr;
	return new cq_mgr_mlx5(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr, m_p_ring->get_tx_comp_event_channel(), false);
}

int qp_mgr_eth_direct::prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr)
{
	qp_init_attr.cap.max_send_wr = m_p_ib_ctx_handler->get_ibv_device_attr()->max_qp_wr;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_inline_data = 0;
#if defined(DEFINED_IBV_DEVICE_CROSS_CHANNEL)
	qp_init_attr.comp_mask |= IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS;
	qp_init_attr.exp_create_flags |= IBV_EXP_QP_CREATE_CROSS_CHANNEL;
	qp_logdbg("Cross-Channel is in qp");
#else
	qp_logdbg("Cross-Channel is not supported in qp");
#endif /* DEFINED_IBV_DEVICE_CROSS_CHANNEL */
	return qp_mgr_eth_mlx5::prepare_ibv_qp(qp_init_attr);
}

void qp_mgr_eth_direct::up()
{
	init_sq();
	m_p_last_tx_mem_buf_desc = NULL;
	modify_qp_to_ready_state();
	m_p_cq_mgr_rx->add_qp_rx(this);
}

void qp_mgr_eth_direct::down()
{
	qp_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_qp));
	modify_qp_to_error_state();

	// let the QP drain all wqe's to flushed cqe's now that we moved
	// it to error state and post_sent final trigger for completion
	usleep(1000);

	m_p_cq_mgr_rx->del_qp_rx(this);
}

bool qp_mgr_eth_direct::fill_hw_descriptors(vma_mlx_hw_device_data &data)
{
	qp_logdbg("QPN: %d dbrec: %p QP.info.SQ. buf: %p wqe_cnt: %d "
		"stride: %d bf.reg: %p",
		m_mlx5_qp.qpn, m_mlx5_qp.sq.dbrec, m_mlx5_qp.sq.buf, m_mlx5_qp.sq.wqe_cnt,
		m_mlx5_qp.sq.stride, m_mlx5_qp.bf.reg);

	data.sq_data.sq_num = m_mlx5_qp.qpn;
	data.sq_data.wq_data.dbrec = m_mlx5_qp.sq.dbrec;
	data.sq_data.wq_data.buf = m_mlx5_qp.sq.buf;
	data.sq_data.wq_data.stride = m_mlx5_qp.sq.stride;
	data.sq_data.wq_data.wqe_cnt = m_mlx5_qp.sq.wqe_cnt;

	data.sq_data.bf.reg = m_mlx5_qp.bf.reg;
	data.sq_data.bf.offset = m_mlx5_qp.bf.offset;
	data.sq_data.bf.size = m_mlx5_qp.bf.size;

	data.rq_data.wq_data.buf = m_mlx5_qp.rq.buf;
	data.rq_data.wq_data.dbrec = m_mlx5_qp.rq.dbrec;
	data.rq_data.wq_data.stride = m_mlx5_qp.rq.stride;
	data.rq_data.wq_data.wqe_cnt = m_mlx5_qp.rq.wqe_cnt;
	data.rq_data.head = &m_mlx5_qp.rq.head;
	data.rq_data.tail = &m_mlx5_qp.rq.tail;

	return true;
}

qp_mgr_eth_direct::~qp_mgr_eth_direct()
{
	if (m_qp) {
		IF_VERBS_FAILURE(ibv_destroy_qp(m_qp)) {
			qp_logdbg("QP destroy failure (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_qp, sizeof(ibv_qp));
	}
	m_qp = NULL;
	delete m_p_cq_mgr_tx;
	m_p_cq_mgr_tx = NULL;
	delete m_p_cq_mgr_rx;
	m_p_cq_mgr_rx = NULL;
}

#endif /* DEFINED_DIRECT_VERBS */
