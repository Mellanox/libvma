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

#include <dev/qp_mgr_mp.h>

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
	uint32_t cq_size = align32pow2(((1 << m_p_ring->get_strides_num()) *
				       m_p_ring->get_wq_count()));
	return new cq_mgr_mp(m_p_ring, m_p_ib_ctx_handler, cq_size,
			     p_rx_comp_event_channel, true,
			     m_p_ring->get_stride_size());
}

int qp_mgr_mp::post_qp_create(void)
{
	vma_ibv_device_attr& r_ibv_dev_attr =
			m_p_ib_ctx_handler->get_ibv_device_attr();
	// create RX resources
	// create WQ
	struct ibv_exp_wq_init_attr wq_init_attr;
	memset(&wq_init_attr, 0, sizeof(wq_init_attr));

	wq_init_attr.wq_type = IBV_EXP_WQT_RQ;
	wq_init_attr.max_recv_wr = m_p_ring->get_wq_count();
	wq_init_attr.max_recv_sge = 1;
	wq_init_attr.pd = m_p_ib_ctx_handler->get_ibv_pd();
	wq_init_attr.cq = m_p_cq_mgr_rx->get_ibv_cq_hndl();
	if (r_ibv_dev_attr.wq_vlan_offloads_cap &
	    IBV_EXP_RECEIVE_WQ_CVLAN_STRIP) {
		wq_init_attr.comp_mask |= IBV_EXP_CREATE_WQ_VLAN_OFFLOADS;
		wq_init_attr.vlan_offloads |= IBV_EXP_RECEIVE_WQ_CVLAN_STRIP;
	}
	wq_init_attr.comp_mask |= IBV_EXP_CREATE_WQ_RES_DOMAIN;
	wq_init_attr.res_domain = m_p_ring->get_res_domain();

	wq_init_attr.comp_mask |= IBV_EXP_CREATE_WQ_MP_RQ;
	wq_init_attr.mp_rq.use_shift = IBV_EXP_MP_RQ_NO_SHIFT;
	wq_init_attr.mp_rq.single_wqe_log_num_of_strides =
					m_p_ring->get_strides_num();
	wq_init_attr.mp_rq.single_stride_log_num_of_bytes =
					m_p_ring->get_stride_size();

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
		return -1;
	}

	struct ibv_exp_query_intf_params intf_params;
	enum ibv_exp_query_intf_status intf_status;

	memset(&intf_params, 0, sizeof(intf_params));
	intf_params.intf_scope = IBV_EXP_INTF_GLOBAL;
	intf_params.intf = IBV_EXP_INTF_WQ;
	intf_params.obj = m_p_wq;
	m_p_wq_family = (struct ibv_exp_wq_family *)
			ibv_exp_query_intf(m_p_ib_ctx_handler->get_ibv_context(),
					   &intf_params, &intf_status);
	if (!m_p_wq_family) {
		qp_logerr("ibv_exp_query_intf failed (errno=%d %m) status %d ",
			errno, intf_status);
		return -1;
	}
	// create indirect table
	struct ibv_exp_rwq_ind_table_init_attr rwq_ind_table_init_attr;

	rwq_ind_table_init_attr.pd = m_p_ib_ctx_handler->get_ibv_pd();
	rwq_ind_table_init_attr.log_ind_tbl_size = 0; // ignore hash
	rwq_ind_table_init_attr.ind_tbl = &m_p_wq;
	rwq_ind_table_init_attr.comp_mask = 0;
	m_p_rwq_ind_tbl =
		ibv_exp_create_rwq_ind_table(m_p_ib_ctx_handler->get_ibv_context(),
					     &rwq_ind_table_init_attr);
	if (!m_p_rwq_ind_tbl) {
		qp_logerr("ibv_exp_create_rwq_ind_table failed (errno=%d %m)", errno);
		return -1;
	}

	// Create rx_hash_conf
	struct ibv_exp_rx_hash_conf rx_hash_conf;

	memset(&rx_hash_conf, 0, sizeof(rx_hash_conf));
	const int TOEPLITZ_RX_HASH_KEY_LEN = 40;
	uint8_t toeplitz_key[] = { 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
				   0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
				   0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
				   0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
				   0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa };
	rx_hash_conf.rx_hash_function = IBV_EXP_RX_HASH_FUNC_TOEPLITZ;
	rx_hash_conf.rx_hash_key_len = TOEPLITZ_RX_HASH_KEY_LEN;
	rx_hash_conf.rx_hash_key = toeplitz_key;
	rx_hash_conf.rx_hash_fields_mask = IBV_EXP_RX_HASH_DST_PORT_UDP;
	rx_hash_conf.rwq_ind_tbl = m_p_rwq_ind_tbl;

	struct ibv_exp_qp_init_attr exp_qp_init_attr;
	memset(&exp_qp_init_attr, 0, sizeof(exp_qp_init_attr));

	exp_qp_init_attr.comp_mask = IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS |
				     IBV_EXP_QP_INIT_ATTR_PD |
				     IBV_EXP_QP_INIT_ATTR_RX_HASH |
				     IBV_EXP_QP_INIT_ATTR_RES_DOMAIN |
				     IBV_EXP_QP_INIT_ATTR_PORT;
	exp_qp_init_attr.rx_hash_conf = &rx_hash_conf;
	exp_qp_init_attr.port_num = 1;
	exp_qp_init_attr.res_domain = m_p_ring->get_res_domain();
	exp_qp_init_attr.pd = m_p_ib_ctx_handler->get_ibv_pd();
	exp_qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
	// Create the QP
	m_qp = ibv_exp_create_qp(m_p_ib_ctx_handler->get_ibv_context(),
				 &exp_qp_init_attr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_qp) {
		qp_logerr("ibv_create_qp failed (errno=%d %m)", errno);
		return -1;
	}

	// initlize the sge, the same sg will be used for all operations
	uint8_t *ptr = (uint8_t *)(((unsigned long)m_p_ring->get_mem_block()) & (~MCE_ALIGNMENT));
	int stride_size = 1 << m_p_ring->get_stride_size();
	int strides_num = 1 << m_p_ring->get_strides_num();
	int size = stride_size * strides_num;

	uint32_t lkey = m_p_ring->get_mem_lkey(m_p_ib_ctx_handler);
	for (uint32_t i = 0; i < m_n_sysvar_rx_num_wr_to_post_recv; i++) {
		m_ibv_rx_sg_array[i].addr = (uint64_t)ptr;
		m_ibv_rx_sg_array[i].length = size;
		m_ibv_rx_sg_array[i].lkey = lkey;
		qp_logdbg("sge %u addr %p size %d lkey %u", i, ptr, size, lkey);
		ptr += size;
	}
	return 0;
}

int qp_mgr_mp::prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr)
{
	qp_logdbg("");
	int ret = 0;

	qp_init_attr.cap.max_recv_wr = 0;
	qp_init_attr.cap.max_recv_sge = 0;
	qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;

	vma_ibv_qp_init_attr_comp_mask(m_p_ib_ctx_handler->get_ibv_pd(), qp_init_attr);
	m_p_tx_qp = vma_ibv_create_qp(m_p_ib_ctx_handler->get_ibv_pd(), &qp_init_attr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_tx_qp) {
		qp_logerr("ibv_create_qp failed (errno=%d %m)", errno);
		return -1;
	}

	if ((ret = priv_ibv_modify_qp_from_err_to_init_raw(m_p_tx_qp, m_port_num)) != 0) {
		qp_logerr("failed to modify QP from ERR to INIT state (ret = %d)", ret);
		return ret;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	int attr_mask = IBV_QP_CAP;
	struct ibv_qp_attr tmp_ibv_qp_attr;
	struct ibv_qp_init_attr tmp_ibv_qp_init_attr;
	IF_VERBS_FAILURE(ibv_query_qp(m_p_tx_qp, &tmp_ibv_qp_attr,
			(enum ibv_qp_attr_mask)attr_mask, &tmp_ibv_qp_init_attr)) {
		qp_logerr("ibv_query_qp failed (errno=%d %m)", errno);
		return -1;
	} ENDIF_VERBS_FAILURE;
	uint32_t tx_max_inline = safe_mce_sys().tx_max_inline;
	m_max_inline_data = min(tmp_ibv_qp_init_attr.cap.max_inline_data, tx_max_inline);
	qp_logdbg("requested max inline = %d QP, actual max inline = %d, VMA max inline set to %d, max_send_wr=%d, max_recv_wr=%d, max_recv_sge=%d, max_send_sge=%d",
			tx_max_inline, tmp_ibv_qp_init_attr.cap.max_inline_data, m_max_inline_data, qp_init_attr.cap.max_send_wr, qp_init_attr.cap.max_recv_wr, qp_init_attr.cap.max_recv_sge, qp_init_attr.cap.max_send_sge);

	return ret;
}


void qp_mgr_mp::up()
{
	// Add buffers
	qp_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_qp));
	release_tx_buffers();

	/* clean any link to completions with error we might have */
	m_n_unsignaled_count = 0;
	m_p_last_tx_mem_buf_desc = NULL;

	m_p_cq_mgr_rx->add_qp_rx(this);
}

int qp_mgr_mp::post_recv(uint32_t sg_index, uint32_t num_of_sge)
{
	// this function always return 0
	qp_logdbg("calling recv_burst with index %d, num_of_sge %d",
		  sg_index, num_of_sge);
	if (unlikely(num_of_sge + sg_index > m_p_ring->get_wq_count())) {
		qp_logdbg("not enough WQE to post");
		return -1;
	}
	return m_p_wq_family->recv_burst(m_p_wq, &m_ibv_rx_sg_array[sg_index],
			num_of_sge);
}

qp_mgr_mp::~qp_mgr_mp()
{

}
#endif //HAVE_MP_RQ


