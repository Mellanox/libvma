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
#include "qp_mgr_direct.h"
#include "vlogger/vlogger.h"

#if defined(HAVE_INFINIBAND_MLX5_HW_H)

#undef  MODULE_NAME
#define MODULE_NAME 	"qp_mgr_direct"
#define qp_logpanic 	__log_info_panic
#define qp_logerr	__log_info_err
#define qp_logwarn	__log_info_warn
#define qp_loginfo	__log_info_info
#define qp_logdbg	__log_info_dbg
#define qp_logfunc	__log_info_func
#define qp_logfuncall	__log_info_funcall

qp_mgr_direct::qp_mgr_direct(const ring_simple* p_ring,
		const ib_ctx_handler* p_context, const uint8_t port_num,
		ibv_comp_channel* p_rx_comp_event_channel,
		const uint32_t tx_num_wr, const uint16_t vlan):
		qp_mgr_eth_mlx5(p_ring, p_context, port_num, p_rx_comp_event_channel, tx_num_wr, vlan)
{

}

void qp_mgr_direct::up()
{
	init_sq();
	m_p_last_tx_mem_buf_desc = NULL;
	modify_qp_to_ready_state();
	m_p_cq_mgr_rx->add_qp_rx(this);
}

bool qp_mgr_direct::fill_hw_descriptors(vma_mlx_hw_device_data &data)
{
	ibv_mlx5_qp_info qpi;

	memset(&qpi, 0, sizeof(qpi));
	if (ibv_mlx5_exp_get_qp_info(m_qp, &qpi)) {
		return false;
	}
	qp_logdbg("QPN: %d dbrec: %p QP.info.SQ. buf: %p wqe_cnt: %d "
		"stride: %d bf.reg: %p bf.need_lock: %d",
		qpi.qpn, qpi.dbrec, qpi.sq.buf, qpi.sq.wqe_cnt,
		qpi.sq.stride, qpi.bf.reg, qpi.bf.need_lock);
	data.sq_data.sq_num = qpi.qpn;

	data.sq_data.wq_data.buf = qpi.sq.buf;
	data.sq_data.wq_data.dbrec = &qpi.dbrec[MLX5_SND_DBR];
	data.sq_data.wq_data.stride = qpi.sq.stride;
	data.sq_data.wq_data.wqe_cnt = qpi.sq.wqe_cnt;

	data.sq_data.bf.reg = qpi.bf.reg;
	data.sq_data.bf.offset = m_hw_qp->gen_data.bf->offset;
	data.sq_data.bf.size = qpi.bf.size;

	data.rq_data.wq_data.buf = qpi.rq.buf;
	data.rq_data.wq_data.dbrec = &qpi.dbrec[MLX5_RCV_DBR];
	data.rq_data.wq_data.stride = qpi.rq.stride;
	data.rq_data.wq_data.wqe_cnt = qpi.rq.wqe_cnt;

	data.rq_data.head = &m_hw_qp->rq.head;
	data.rq_data.tail = &m_hw_qp->rq.tail;

	return true;
}

qp_mgr_direct::~qp_mgr_direct()
{
}

#endif
