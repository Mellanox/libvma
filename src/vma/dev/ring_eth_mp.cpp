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

#include <dev/ring_eth_mp.h>
#include <dev/qp_mgr_mp.h>

#undef  MODULE_NAME
#define MODULE_NAME		"ring_eth_mp"
#undef  MODULE_HDR
#define MODULE_HDR		MODULE_NAME "%d:%s() "


#ifndef DEFINED_IBV_OLD_VERBS_MLX_OFED

ring_eth_mp::ring_eth_mp(in_addr_t local_if,
			 ring_resource_creation_info_t *p_ring_info, int count,
			 bool active, uint16_t vlan, uint32_t mtu,
			 ring *parent) throw (vma_error) :
			 ring_eth(local_if, p_ring_info, count, active, vlan,
				  mtu, parent, false),
			 m_strides_num(16), m_stride_size(11), m_res_domain(NULL),
			 m_wq_count(2), m_curr_wq(0), m_curr_d_addr(0),
			 m_curr_h_ptr(NULL)
{
	// call function from derived not base
	m_is_mp_ring = true;
	m_buffer_size = (1 << m_stride_size) * (1 << m_strides_num) * m_wq_count + MCE_ALIGNMENT;
	memset(&m_curr_hw_timestamp, 0, sizeof(m_curr_hw_timestamp));
	create_resources(p_ring_info, active);
}

void ring_eth_mp::create_resources(ring_resource_creation_info_t *p_ring_info,
				   bool active) throw (vma_error)
{
	struct ibv_exp_res_domain_init_attr res_domain_attr;

	// check MP capabilities currently all caps are 0 due to a buf
	vma_ibv_device_attr& r_ibv_dev_attr =
			p_ring_info->p_ib_ctx->get_ibv_device_attr();
	if (!r_ibv_dev_attr.max_ctx_res_domain) {
		throw_vma_exception("device doesn't support resource domain");
		return;
	}
	if (!(r_ibv_dev_attr.mp_rq_caps.supported_qps & IBV_EXP_QPT_RAW_PACKET)) {
		throw_vma_exception("device doesn't support RC QP");
	}

	if (m_stride_size <
		r_ibv_dev_attr.mp_rq_caps.min_single_stride_log_num_of_bytes) {
		ring_logwarn("stride byte size is to low, supported %d, given %d",
			     r_ibv_dev_attr.mp_rq_caps.min_single_stride_log_num_of_bytes,
			     m_stride_size);
		throw_vma_exception("stride byte size is to low");
	}
	if (m_stride_size >
		r_ibv_dev_attr.mp_rq_caps.max_single_stride_log_num_of_bytes) {
		ring_logwarn("stride byte size is to high, supported %d, given %d",
			     r_ibv_dev_attr.mp_rq_caps.min_single_stride_log_num_of_bytes,
			     m_stride_size);
		throw_vma_exception("stride byte size is to high");
	}
	if (m_strides_num <
		r_ibv_dev_attr.mp_rq_caps.min_single_wqe_log_num_of_strides) {
		ring_logwarn("strides num is to low, supported %d, given %d",
			     r_ibv_dev_attr.mp_rq_caps.min_single_wqe_log_num_of_strides,
			     m_strides_num);
		throw_vma_exception("strides num is to low");
	}
	if (m_strides_num >
		r_ibv_dev_attr.mp_rq_caps.max_single_wqe_log_num_of_strides) {
		ring_logwarn("strides num is to high, supported %d, given %d",
			     r_ibv_dev_attr.mp_rq_caps.min_single_wqe_log_num_of_strides,
			     m_strides_num);
		throw_vma_exception("strides num is to high");
	}

	res_domain_attr.comp_mask = IBV_EXP_RES_DOMAIN_THREAD_MODEL |
				    IBV_EXP_RES_DOMAIN_MSG_MODEL;

	// driver is in charge of locks
	res_domain_attr.thread_model = IBV_EXP_THREAD_SAFE;

	// currently have no affect
	res_domain_attr.msg_model = IBV_EXP_MSG_HIGH_BW;

	m_res_domain = ibv_exp_create_res_domain(
				p_ring_info->p_ib_ctx->get_ibv_context(),
				&res_domain_attr);
	if (!m_res_domain) {
		throw_vma_exception("failed creating resource domain");
		return;
	}
	// create cyclic buffer get exception on failure
	alloc.allocAndRegMr(m_buffer_size, p_ring_info->p_ib_ctx) ;
	// point m_sge to buffer
	int strides_num = 1 << m_strides_num;
	int strides_length = 1 << m_stride_size;
	ring_logdbg("strides num is %d stride size is %d", strides_num,
		    strides_length);
	// RAFI need to change to nice logic check
	assert(uint32_t(strides_num * strides_length * m_wq_count) < m_buffer_size);
	// create ring simple resources
	ring_simple::create_resources(p_ring_info, active);
	// some detect them as unused
	NOT_IN_USE(strides_num);
	NOT_IN_USE(strides_length);
}

qp_mgr* ring_eth_mp::create_qp_mgr(const ib_ctx_handler *ib_ctx,
				   uint8_t port_num,
				   struct ibv_comp_channel *p_rx_comp_event_channel) throw (vma_error)
{
	return new qp_mgr_mp(this, ib_ctx, port_num, p_rx_comp_event_channel,
			get_tx_num_wr(), get_partition());
}

int ring_eth_mp::drain_and_proccess(cq_type_t cq_type)
{
	(void)cq_type;
	return 0;
}

ring_eth_mp::~ring_eth_mp()
{
	struct ibv_exp_destroy_res_domain_attr attr;

	memset(&attr, 0, sizeof(attr));
	int res = ibv_exp_destroy_res_domain(
			m_p_qp_mgr->get_ib_ctx_handler()->get_ibv_context(),
			m_res_domain,
			&attr);
	if (res)
		ring_logdbg("call to ibv_exp_destroy_res_domain returned %d", res);

}
#endif

