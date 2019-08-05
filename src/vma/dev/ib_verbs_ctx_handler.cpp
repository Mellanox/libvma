/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#include <infiniband/verbs.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/dev/ib_verbs_ctx_handler.h"
#include "vma/util/sys_vars.h"
#include "vma/ib/base/verbs_extra.h"
#include "vma/dev/time_converter_ib_ctx.h"
#include "vma/dev/time_converter_ptp.h"
#include "vma/event/event_handler_manager.h"
#include "vma/dev/ib_ctx_handler.h"
#include "util/valgrind.h"

#define MODULE_NAME             "ibch"

#define ibch_logpanic           __log_panic
#define ibch_logerr             __log_err
#define ibch_logwarn            __log_warn
#define ibch_loginfo            __log_info
#define ibch_logdbg             __log_info_dbg
#define ibch_logfunc            __log_info_func
#define ibch_logfuncall         __log_info_funcall


ib_verbs_ctx_handler::ib_verbs_ctx_handler(struct ib_ctx_handler_desc *desc) :
	ib_ctx_handler(desc)
	, m_lock_umr("spin_lock_umr")
	, m_umr_cq(NULL)
	, m_umr_qp(NULL)

{
	if (!m_p_ibv_device) {
		return;
	}
	// Create pd for this device
	m_p_ibv_context = ibv_open_device(m_p_ibv_device);
	if (m_p_ibv_context == NULL) {
		ibch_logerr("m_p_ibv_context is invalid");
		return;
	}
	m_p_ibv_pd = ibv_alloc_pd(m_p_ibv_context);
	if (m_p_ibv_pd == NULL) {
		ibch_logerr("ibv device %p pd allocation failure (ibv context %p) (errno=%d %m)",
			    m_p_ibv_device, m_p_ibv_context, errno);
		m_is_ok = false;
		return;
	}
}

ib_verbs_ctx_handler::~ib_verbs_ctx_handler()
{
	clean();
	if (m_umr_qp) {
		IF_VERBS_FAILURE_EX(ibv_destroy_qp(m_umr_qp), EIO) {
			ibch_logdbg("destroy qp failed (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		m_umr_qp = NULL;
	}
	if (m_umr_cq) {
		IF_VERBS_FAILURE_EX(ibv_destroy_cq(m_umr_cq), EIO) {
			ibch_logdbg("destroy cq failed (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		m_umr_cq = NULL;
	}
	if (m_p_ibv_pd) {
		IF_VERBS_FAILURE_EX(ibv_dealloc_pd(m_p_ibv_pd), EIO) {
			ibch_logdbg("pd deallocation failure (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_p_ibv_pd, sizeof(struct ibv_pd));
		m_p_ibv_pd = NULL;
	}

	ibv_close_device(m_p_ibv_context);
	m_p_ibv_context = NULL;

	BULLSEYE_EXCLUDE_BLOCK_END
}

bool ib_verbs_ctx_handler::post_umr_wr(vma_ibv_send_wr &wr)
{
#ifdef HAVE_MP_RQ
	auto_unlocker lock(m_lock_umr);
	ibv_exp_send_wr *bad_wr = NULL;
	ibv_exp_wc wc;

	if (!m_umr_qp && !create_umr_qp()) {
		ibch_logwarn("failed creating umr_qp");
		return false;
	}
	int res = ibv_exp_post_send(m_umr_qp, &wr, &bad_wr);

	if (res) {
		if (bad_wr) {
			ibch_logdbg("bad_wr info: wr_id=%#x, send_flags=%#x, "
				    "addr=%#x, length=%d, lkey=%#x",
				    bad_wr->wr_id,
				    bad_wr->exp_send_flags,
				    bad_wr->sg_list[0].addr,
				    bad_wr->sg_list[0].length,
				    bad_wr->sg_list[0].lkey);
		}
		return false;
	}
	int ret;
	do {
		ret = ibv_exp_poll_cq(m_umr_cq, 1, &wc, sizeof(wc));
		if (ret < 0) {
			ibch_logdbg("poll CQ failed after %d errno:%d\n", ret, errno);
			return false;
		}
	} while (!ret);

	if (wc.status != IBV_WC_SUCCESS) {
		ibch_logdbg("post_umr_wr comp status %d\n", wc.status);
		return false;
	}
	return true;
#else
	NOT_IN_USE(wr);
	return false;
#endif
}

bool ib_verbs_ctx_handler::create_umr_qp()
{
#ifdef HAVE_MP_RQ
	ibch_logdbg("");
	int ret = 0;
	uint8_t *gid_raw;
	const int port_num = 1;
	//create TX_QP & CQ for UMR
	vma_ibv_cq_init_attr cq_attr;
	memset(&cq_attr, 0, sizeof(cq_attr));

	m_umr_cq = vma_ibv_create_cq(m_p_ibv_context, 16, NULL, NULL, 0, &cq_attr);
	if (m_umr_cq == NULL) {
		ibch_logdbg("failed creating UMR CQ (errno=%d %m)", errno);
		return false;
	}
	// Create QP
	vma_ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.recv_cq = m_umr_cq;
	qp_init_attr.send_cq = m_umr_cq;
	qp_init_attr.cap.max_send_wr = 16;
	qp_init_attr.cap.max_recv_wr = 16;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	vma_ibv_qp_init_attr_comp_mask(m_p_ibv_pd, qp_init_attr);
	qp_init_attr.comp_mask |= IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS |
				  IBV_EXP_QP_INIT_ATTR_MAX_INL_KLMS;
	qp_init_attr.exp_create_flags |= IBV_EXP_QP_CREATE_UMR;
	// max UMR needed is 4, in STRIP with HEADER mode. net, hdr, payload, padding
	qp_init_attr.max_inl_send_klms = 4;
	m_umr_qp = vma_ibv_create_qp(m_p_ibv_pd, &qp_init_attr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_umr_qp) {
		ibch_logdbg("vma_ibv_create_qp failed (errno=%d %m)", errno);
		goto err_destroy_cq;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	// Modify QP to INIT state
	struct ibv_qp_attr qp_attr;
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = port_num;
	ret = ibv_modify_qp(m_umr_qp, &qp_attr,
			IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
	if (ret) {
		ibch_logdbg("Failed to modify UMR QP to INIT: (errno=%d %m)", errno);
		goto err_destroy_qp;
	}
	// Modify to RTR
	qp_attr.qp_state = IBV_QPS_RTR;
	qp_attr.dest_qp_num = m_umr_qp->qp_num;
	memset(&qp_attr.ah_attr, 0, sizeof(qp_attr.ah_attr));
	qp_attr.ah_attr.port_num = port_num;
	qp_attr.ah_attr.is_global = 1;
	if (ibv_query_gid(m_p_ibv_context, port_num,
			  0, &qp_attr.ah_attr.grh.dgid)) {
		ibch_logdbg("Failed getting port gid: (errno=%d %m)", errno);
		goto err_destroy_qp;
	}
	gid_raw = qp_attr.ah_attr.grh.dgid.raw;
	if ((*(uint64_t *)gid_raw == 0) && (*(uint64_t *)(gid_raw + 8) == 0)) {
		ibch_logdbg("Port gid is zero: (errno=%d %m)", errno);
		goto err_destroy_qp;
	}
	qp_attr.path_mtu = IBV_MTU_512;
	qp_attr.min_rnr_timer = 7;
	qp_attr.max_dest_rd_atomic = 1;
	ret = ibv_modify_qp(m_umr_qp, &qp_attr,
			IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
			IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
	if (ret) {
		ibch_logdbg("Failed to modify UMR QP to RTR:(errno=%d %m)", errno);
		goto err_destroy_qp;
	}

	/* Modify to RTS */
	qp_attr.qp_state = IBV_QPS_RTS;
	qp_attr.sq_psn = 0;
	qp_attr.timeout = 7;
	qp_attr.rnr_retry = 7;
	qp_attr.retry_cnt = 7;
	qp_attr.max_rd_atomic = 1;
	ret = ibv_modify_qp(m_umr_qp, &qp_attr,
			IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
			IBV_QP_MAX_QP_RD_ATOMIC);
	if (ret) {
		ibch_logdbg("Failed to modify UMR QP to RTS:(errno=%d %m)", errno);
		goto err_destroy_qp;
	}

	return true;
err_destroy_qp:
	IF_VERBS_FAILURE(ibv_destroy_qp(m_umr_qp)) {
		ibch_logdbg("destroy qp failed (errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;
	m_umr_qp = NULL;
err_destroy_cq:
	IF_VERBS_FAILURE(ibv_destroy_cq(m_umr_cq)) {
		ibch_logdbg("destroy cq failed (errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;
	m_umr_cq = NULL;
	return false;
#else
	return false;
#endif
}
