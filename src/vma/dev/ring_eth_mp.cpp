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
			 m_wq_count(2)
{
	m_buffer_size = (1 << m_stride_size) * (1 << m_strides_num) * m_wq_count + MCE_ALIGNMENT;
	create_resources(p_ring_info, active);
}
#endif
