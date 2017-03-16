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

#ifndef SRC_VMA_DEV_QP_MGR_MP_H_
#define SRC_VMA_DEV_QP_MGR_MP_H_

#include "dev/qp_mgr.h"
#include "dev/ring_eth_mp.h"
#include "dev/cq_mgr_mp.h"

#ifdef HAVE_INFINIBAND_MLX5_HW_H

class cq_mgr_mp;

class qp_mgr_mp : public qp_mgr_eth
{
public:
	qp_mgr_mp(const ring_eth_mp *p_ring, const ib_ctx_handler *p_context,
		  const uint8_t port_num,
		  struct ibv_comp_channel *p_rx_comp_event_channel,
		  const uint32_t tx_num_wr, const uint16_t vlan)
		  throw (vma_error) : qp_mgr_eth((const ring_simple *)p_ring,
						 p_context, port_num,
						 p_rx_comp_event_channel,
						 tx_num_wr, vlan, false) {
		m_p_ring = const_cast<ring_eth_mp *>(p_ring);
		m_n_sysvar_rx_num_wr_to_post_recv = p_ring->get_wq_count();
		if (configure(p_rx_comp_event_channel))
			throw_vma_exception("failed creating qp");
	};
	virtual		~qp_mgr_mp();
	virtual void	up();
	int		post_recv(uint32_t sg_index, uint32_t num_of_sge);
	int		get_strides_num() {return m_p_ring->get_strides_num();}
	int		get_wq_count() {return m_p_ring->get_wq_count();}
protected:
	virtual cq_mgr* init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual int	prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr);
	virtual int	post_qp_create(void);
private:
	// override parent ring
	ring_eth_mp*			m_p_ring;
	struct ibv_exp_wq*		m_p_wq;
	struct ibv_exp_wq_family*	m_p_wq_family;
	struct ibv_exp_rwq_ind_table*	m_p_rwq_ind_tbl;
	struct ibv_qp*			m_p_tx_qp;
};
#endif

#endif /* SRC_VMA_DEV_QP_MGR_MP_H_ */
