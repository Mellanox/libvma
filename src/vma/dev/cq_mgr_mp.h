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

#ifndef SRC_VMA_DEV_CQ_MGR_MP_H_
#define SRC_VMA_DEV_CQ_MGR_MP_H_

#include "dev/cq_mgr.h"
#include "dev/ring_eth_mp.h"
#include "dev/qp_mgr_mp.h"

#ifdef HAVE_INFINIBAND_MLX5_HW_H

class qp_mgr_mp;

class cq_mgr_mp : public cq_mgr_mlx5
{
	struct ibv_exp_res_domain_init_attr res_domain_attr;
public:

	cq_mgr_mp(ring_eth_mp *p_ring, ib_ctx_handler *p_ib_ctx_handler,
		  uint32_t cq_size,
		  struct ibv_comp_channel *p_comp_event_channel,
		  bool is_rx, int stride_size);
	~cq_mgr_mp();
	int		poll_mp_cq(uint16_t &size, uint16_t &strides_used,
				   uint32_t &offset, uint32_t &flags,
				   volatile struct mlx5_cqe64 *&cqe64);
protected:
	virtual void	prep_ibv_cq(vma_ibv_cq_init_attr &attr);
	virtual void	add_qp_rx(qp_mgr *qp);
private:
	ring_eth_mp			*m_p_ring;
	uint32_t			m_pow_stride_size;
};
#endif // DEFINED_IBV_OLD_VERBS_MLX_OFED

#endif /* SRC_VMA_DEV_CQ_MGR_MP_H_ */
