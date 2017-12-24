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

#include "ring_direct.h"
#include "qp_mgr_direct.h"


#undef  MODULE_NAME
#define MODULE_NAME		"ring_direct"
#undef  MODULE_HDR
#define MODULE_HDR		MODULE_NAME "%d:%s() "


ring_direct::ring_direct(in_addr_t local_if,
			 ring_resource_creation_info_t *p_ring_info, int count,
			 bool active, uint16_t vlan, uint32_t mtu,
			 vma_external_mem_attr *ext_ring_attr, ring *parent):
			 ring_eth(local_if, p_ring_info, count, active, vlan,
				  mtu, parent, false)
{
	m_ring_attr.comp_mask = ext_ring_attr->comp_mask;
	create_resources(p_ring_info, active);
}

qp_mgr* ring_direct::create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel)
{
#if defined(HAVE_INFINIBAND_MLX5_HW_H)
	return new qp_mgr_direct(this, ib_ctx, port_num, p_rx_comp_event_channel,
				get_tx_num_wr(), get_partition());
#endif
	NOT_IN_USE(ib_ctx);
	NOT_IN_USE(port_num);
	NOT_IN_USE(p_rx_comp_event_channel);
	return NULL;
}

void ring_direct::init_tx_buffers(uint32_t count)
{
	NOT_IN_USE(count);
}

int ring_direct::mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list,
				    bool b_accounting, bool trylock)
{
	NOT_IN_USE(p_mem_buf_desc_list);
	NOT_IN_USE(b_accounting);
	NOT_IN_USE(trylock);
	return 0;
}

int ring_direct::drain_and_proccess(cq_type_t cq_type)
{
	NOT_IN_USE(cq_type);
	return 0;
}

int ring_direct::poll_and_process_element_rx(uint64_t* p_cq_poll_sn,
						   void* pv_fd_ready_array)
{
	NOT_IN_USE(p_cq_poll_sn);
	NOT_IN_USE(pv_fd_ready_array);
	return 0;
}

int ring_direct::get_ring_descriptors(vma_mlx_hw_device_data &d)
{

	d.dev_data.vendor_id = m_p_ib_ctx->get_ibv_device_attr()->vendor_id;
	d.dev_data.vendor_part_id = m_p_ib_ctx->get_ibv_device_attr()->vendor_part_id;
	d.dev_data.device_cap = 0;
	d.valid_mask = DATA_VALID_DEV;

	if (!m_p_qp_mgr->fill_hw_descriptors(d)) {
		return -1;
	}
	if (!m_p_cq_mgr_rx->fill_cq_hw_descriptors(d.rq_data.wq_data.cq_data)) {
		return -1;
	}
	d.valid_mask |= DATA_VALID_RQ;
	if (!m_p_cq_mgr_tx->fill_cq_hw_descriptors(d.sq_data.wq_data.cq_data)) {
		return -1;
	}
	d.valid_mask |= DATA_VALID_SQ;
	return 0;
}
