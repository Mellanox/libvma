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

#include <dev/qp_mgr_mp.h>
#include "dev/cq_mgr_mp.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"qpmp"

#define qp_logpanic 		__log_info_panic
#define qp_logerr		__log_info_err
#define qp_logwarn		__log_info_warn
#define qp_loginfo		__log_info_info
#define qp_logdbg		__log_info_dbg
#define qp_logfunc		__log_info_func
#define qp_logfuncall		__log_info_funcall


#ifdef HAVE_MP_RQ


cq_mgr* qp_mgr_mp::init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel)
{
	// CQ size should be aligned to power of 2 due to PRM
	// also it size is the max CQs we can hold at once
	// this equals to number of strides in WQe * WQ's
	uint32_t cq_size = align32pow2((m_p_mp_ring->get_strides_num() *
					m_p_mp_ring->get_wq_count()));
	return new cq_mgr_mp(m_p_mp_ring, m_p_ib_ctx_handler, cq_size,
			     p_rx_comp_event_channel, true, m_external_mem);
}

int qp_mgr_mp::prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr)
{
	NOT_IN_USE(qp_init_attr);
	struct ibv_exp_rx_hash_conf rx_hash_conf;
	struct ibv_exp_query_intf_params query_intf_params;
	struct ibv_exp_release_intf_params rel_intf_params;
	struct ibv_exp_rwq_ind_table_init_attr rwq_ind_table_init_attr;
	struct ibv_exp_qp_init_attr exp_qp_init_attr;
	enum ibv_exp_query_intf_status intf_status;
	uint32_t lkey;
	uint8_t *ptr;
	uint32_t size;
	uint8_t toeplitz_key[] = { 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
				   0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
				   0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
				   0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
				   0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa };
	const int TOEPLITZ_RX_HASH_KEY_LEN =
			sizeof(toeplitz_key)/sizeof(toeplitz_key[0]);
	// create RX resources
	// create WQ
	struct ibv_exp_wq_init_attr wq_init_attr;
	memset(&wq_init_attr, 0, sizeof(wq_init_attr));

	wq_init_attr.wq_type = IBV_EXP_WQT_RQ;
	wq_init_attr.max_recv_wr = m_p_mp_ring->get_wq_count();
	wq_init_attr.max_recv_sge = 1;
	wq_init_attr.pd = m_p_ib_ctx_handler->get_ibv_pd();
	wq_init_attr.cq = m_p_cq_mgr_rx->get_ibv_cq_hndl();
	wq_init_attr.comp_mask |= IBV_EXP_CREATE_WQ_RES_DOMAIN;
	wq_init_attr.res_domain = m_p_mp_ring->get_res_domain();

	wq_init_attr.comp_mask |= IBV_EXP_CREATE_WQ_MP_RQ;
	wq_init_attr.mp_rq.use_shift = IBV_EXP_MP_RQ_NO_SHIFT;
	wq_init_attr.mp_rq.single_wqe_log_num_of_strides =
				m_p_mp_ring->get_single_wqe_log_num_of_strides();
	wq_init_attr.mp_rq.single_stride_log_num_of_bytes =
				m_p_mp_ring->get_single_stride_log_num_of_bytes();

	m_p_wq = ibv_exp_create_wq(m_p_ib_ctx_handler->get_ibv_context(),
			&wq_init_attr);
	if (!m_p_wq) {
		qp_logerr("ibv_exp_create_wq failed (errno=%d %m)", errno);
		return -1;
	}

	// change WQ to ready state
	struct ibv_exp_wq_attr wq_attr;

	memset(&wq_attr, 0, sizeof(wq_attr));
	wq_attr.attr_mask = IBV_EXP_WQ_ATTR_STATE;
	wq_attr.wq_state = IBV_EXP_WQS_RDY;

	if (ibv_exp_modify_wq(m_p_wq, &wq_attr)) {
		qp_logerr("failed changing WQ state (errno=%d %m)", errno);
		goto err;
	}

	intf_status = IBV_EXP_INTF_STAT_OK;

	memset(&query_intf_params, 0, sizeof(query_intf_params));
	query_intf_params.intf_scope = IBV_EXP_INTF_GLOBAL;
	query_intf_params.intf = IBV_EXP_INTF_WQ;
	query_intf_params.obj = m_p_wq;
	m_p_wq_family = (struct ibv_exp_wq_family *)
			ibv_exp_query_intf(m_p_ib_ctx_handler->get_ibv_context(),
					   &query_intf_params, &intf_status);
	if (!m_p_wq_family) {
		qp_logerr("ibv_exp_query_intf failed (errno=%m) status %d ",
			errno, intf_status);
		goto err;
	}
	// create indirect table
	rwq_ind_table_init_attr.pd = m_p_ib_ctx_handler->get_ibv_pd();
	rwq_ind_table_init_attr.log_ind_tbl_size = 0; // ignore hash
	rwq_ind_table_init_attr.ind_tbl = &m_p_wq;
	rwq_ind_table_init_attr.comp_mask = 0;
	m_p_rwq_ind_tbl =
		ibv_exp_create_rwq_ind_table(m_p_ib_ctx_handler->get_ibv_context(),
					     &rwq_ind_table_init_attr);
	if (!m_p_rwq_ind_tbl) {
		qp_logerr("ibv_exp_create_rwq_ind_table failed (errno=%d %m)", errno);
		goto err;
	}

	// Create rx_hash_conf
	memset(&rx_hash_conf, 0, sizeof(rx_hash_conf));
	rx_hash_conf.rx_hash_function = IBV_EXP_RX_HASH_FUNC_TOEPLITZ;
	rx_hash_conf.rx_hash_key_len = TOEPLITZ_RX_HASH_KEY_LEN;
	rx_hash_conf.rx_hash_key = toeplitz_key;
	rx_hash_conf.rx_hash_fields_mask = IBV_EXP_RX_HASH_DST_PORT_UDP;
	rx_hash_conf.rwq_ind_tbl = m_p_rwq_ind_tbl;

	memset(&exp_qp_init_attr, 0, sizeof(exp_qp_init_attr));

	exp_qp_init_attr.comp_mask = IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS |
				     IBV_EXP_QP_INIT_ATTR_PD |
				     IBV_EXP_QP_INIT_ATTR_RX_HASH |
				     IBV_EXP_QP_INIT_ATTR_RES_DOMAIN;
	exp_qp_init_attr.rx_hash_conf = &rx_hash_conf;
	exp_qp_init_attr.res_domain = m_p_mp_ring->get_res_domain();
	exp_qp_init_attr.pd = m_p_ib_ctx_handler->get_ibv_pd();
	exp_qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
	// Create the QP
	m_qp = ibv_exp_create_qp(m_p_ib_ctx_handler->get_ibv_context(),
				 &exp_qp_init_attr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_qp) {
		qp_logerr("ibv_create_qp failed (errno=%d %m)", errno);
		goto err;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	// initlize the sge, the same sg will be used for all operations
	ptr = (uint8_t *)m_buff_data.addr;
	lkey = m_buff_data.lkey;
	size = m_buff_data.length;
	// initlize the sge, the same sg will be used for all operations
	for (uint32_t i = 0; i < m_n_sysvar_rx_num_wr_to_post_recv; i++) {
		m_ibv_rx_sg_array[i].addr = (uint64_t)ptr;
		m_ibv_rx_sg_array[i].length = size;
		m_ibv_rx_sg_array[i].lkey = lkey;
		qp_logdbg("sge %u addr %p - %p size %d lkey %u",
			  i, ptr, ptr + size, size, lkey);
		ptr += size;
	}
	return 0;
err:
	if (m_qp) {
		IF_VERBS_FAILURE(ibv_destroy_qp(m_qp)) {
				qp_logerr("TX QP destroy failure (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
	}
	if (m_p_rwq_ind_tbl) {
		IF_VERBS_FAILURE(ibv_exp_destroy_rwq_ind_table(m_p_rwq_ind_tbl)) {
				qp_logerr("ibv_exp_destroy_rwq_ind_table "
					 "failed (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
	}
	if (m_p_wq_family) {
		memset(&rel_intf_params, 0, sizeof(rel_intf_params));
		IF_VERBS_FAILURE(ibv_exp_release_intf(m_p_ib_ctx_handler->get_ibv_context(),
				m_p_wq_family, &rel_intf_params)) {
			qp_logerr("ibv_exp_release_intf failed (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
	}
	if (m_p_wq) {
		IF_VERBS_FAILURE(ibv_exp_destroy_wq(m_p_wq)) {
			qp_logerr("ibv_exp_destroy_wq failed (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
	}
	return -1;
}


void qp_mgr_mp::up()
{
	m_p_cq_mgr_rx->add_qp_rx(this);
}

int qp_mgr_mp::post_recv(uint32_t sg_index, uint32_t num_of_sge)
{
	// this function always return 0
	qp_logdbg("calling recv_burst with index %d, num_of_sge %d",
		  sg_index, num_of_sge);
	if (unlikely(num_of_sge + sg_index > m_p_mp_ring->get_wq_count())) {
		qp_logdbg("not enough WQE to post");
		return -1;
	}
	return m_p_wq_family->recv_burst(m_p_wq, &m_ibv_rx_sg_array[sg_index],
			num_of_sge);
}

bool qp_mgr_mp::fill_hw_descriptors(vma_mlx_hw_device_data &data)
{
	struct mlx5_rwq *mrwq = container_of(m_p_wq, struct mlx5_rwq, wq);

	data.rq_data.wq_data.buf       = (uint8_t *)mrwq->buf.buf + mrwq->rq.offset;
	data.rq_data.wq_data.dbrec     = mrwq->db;
	data.rq_data.wq_data.wqe_cnt   = mrwq->rq.wqe_cnt;
	data.rq_data.wq_data.stride    = (1 << mrwq->rq.wqe_shift);

	qp_logdbg("QP: %d  WQ: dbrec: %p buf: %p wqe_cnt: %d stride: %d ",
		m_qp->qp_num, data.rq_data.wq_data.dbrec,
		data.rq_data.wq_data.buf, data.rq_data.wq_data.wqe_cnt,
		data.rq_data.wq_data.stride);
	return true;
}

qp_mgr_mp::~qp_mgr_mp()
{
	// destroy RX QP
	if (m_qp) {
		IF_VERBS_FAILURE(ibv_destroy_qp(m_qp)) {
			qp_logerr("TX QP destroy failure (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
		m_qp = NULL;
	}

	if (m_p_wq_family) {
		ibv_exp_release_intf_params params;
		memset(&params, 0, sizeof(params));
		IF_VERBS_FAILURE(ibv_exp_release_intf(m_p_ib_ctx_handler->get_ibv_context(),
				m_p_wq_family, &params)) {
			qp_logerr("ibv_exp_release_intf failed (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
	}

	if (m_p_rwq_ind_tbl) {
		IF_VERBS_FAILURE(ibv_exp_destroy_rwq_ind_table(m_p_rwq_ind_tbl)) {
			qp_logerr("ibv_exp_destroy_rwq_ind_table failed (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
	}

	if (m_p_wq) {
		IF_VERBS_FAILURE(ibv_exp_destroy_wq(m_p_wq)) {
			qp_logerr("ibv_exp_destroy_wq failed (errno = %d %m)", -errno);
		} ENDIF_VERBS_FAILURE;
	}

	delete m_p_cq_mgr_tx;
	m_p_cq_mgr_tx = NULL;

	delete m_p_cq_mgr_rx;
	m_p_cq_mgr_rx = NULL;
}
#endif //HAVE_MP_RQ


