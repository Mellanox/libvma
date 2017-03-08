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

#ifndef SRC_VMA_DEV_RING_ETH_MP_H_
#define SRC_VMA_DEV_RING_ETH_MP_H_

#include <dev/ring_simple.h>

#ifndef DEFINED_IBV_OLD_VERBS_MLX_OFED

class cq_mgr_mp;


class ring_eth_mp : public ring_eth
{
public:
	ring_eth_mp(in_addr_t local_if,
		    ring_resource_creation_info_t *p_ring_info, int count,
		    bool active, uint16_t vlan, uint32_t mtu,
		    ring *parent = NULL) throw (vma_error);
	virtual ~ring_eth_mp();
	struct ibv_exp_res_domain* get_res_domain() {return m_res_domain;};
		int get_strides_num() const {return m_strides_num;};
	int get_stride_size() const {return m_stride_size;};
	uint32_t get_wq_count() const {return m_wq_count;};
	void* get_mem_block() {return alloc.get_ptr();};
	uint32_t get_mem_lkey(ib_ctx_handler* ib_ctx) {return alloc.find_lkey_by_ib_ctx(ib_ctx);}
	
protected:

private:
	vma_allocator			alloc;
	int				m_strides_num;
	int				m_stride_size;
	struct ibv_exp_res_domain*	m_res_domain;
	size_t				m_buffer_size;
	uint32_t			m_wq_count;
};

#endif /* DEFINED_IBV_OLD_VERBS_MLX_OFED */
#endif /* SRC_VMA_DEV_RING_ETH_MP_H_ */
