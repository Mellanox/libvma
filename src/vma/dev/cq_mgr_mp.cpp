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


#ifndef DEFINED_IBV_OLD_VERBS_MLX_OFED

cq_mgr_mp::cq_mgr_mp(ring_eth_mp *p_ring, ib_ctx_handler *p_ib_ctx_handler,
		     int cq_size, struct ibv_comp_channel *p_comp_event_channel,
		     bool is_rx):
		     cq_mgr((ring_simple*)p_ring, p_ib_ctx_handler,
			    cq_size , p_comp_event_channel, is_rx, false),
		     m_p_ring(p_ring), m_p_cq_family1(NULL)
{
	// must call from derive in order to call derived hooks
	configure(cq_size);
}

void cq_mgr_mp::prep_ibv_cq(vma_ibv_cq_init_attr &attr)
{
	cq_mgr::prep_ibv_cq(attr);
	attr.comp_mask |= IBV_EXP_CQ_INIT_ATTR_RES_DOMAIN;
	attr.res_domain = m_p_ring->get_res_domain();
}

int cq_mgr_mp::post_ibv_cq()
{
	struct ibv_exp_query_intf_params intf_params;
	enum ibv_exp_query_intf_status intf_status;

	memset(&intf_params, 0, sizeof(intf_params));
	intf_params.intf_scope = IBV_EXP_INTF_GLOBAL;
	intf_params.intf_version = 1;
	intf_params.intf = IBV_EXP_INTF_CQ;
	intf_params.obj = m_p_ibv_cq;

	m_p_cq_family1 = (struct ibv_exp_cq_family_v1 *)
		ibv_exp_query_intf(m_p_ib_ctx_handler->get_ibv_context(),
				&intf_params, &intf_status);
	if (!m_p_cq_family1) {
		return -1;
	}
	return 0;

}

void cq_mgr_mp::add_qp_rx(qp_mgr *_qp)
{
	cq_logdbg("qp_mgr=%p", _qp);
	qp_mgr_mp* qp = (qp_mgr_mp *)_qp;
	m_p_cq_stat->n_rx_drained_at_once_max = 0;

	for (int i = 0; i < qp->get_wq_count(); i++) {
		if (qp->post_recv() != 0) {
			cq_logdbg("qp post recv failed");
			break;
		}
	}

	cq_logdbg("Successfully post_recv qp with %d new Rx buffers",
		  qp->get_wq_count());
}

#endif //DEFINED_IBV_OLD_VERBS_MLX_OFED

