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

#ifndef SRC_VMA_DEV_QP_MGR_MP_H_
#define SRC_VMA_DEV_QP_MGR_MP_H_

#include "dev/qp_mgr.h"
#include "dev/ring_eth_cb.h"

#ifdef HAVE_MP_RQ

class qp_mgr_mp : public qp_mgr_eth
{
public:
	qp_mgr_mp(const ring_eth_cb *p_ring, const ib_ctx_handler *p_context,
		  const uint8_t port_num,
		  struct ibv_comp_channel *p_rx_comp_event_channel,
		  const uint32_t tx_num_wr, const uint16_t vlan, ibv_sge &buff_d,
		  bool external_mem) :
		  qp_mgr_eth(p_ring, p_context, port_num,
			     p_rx_comp_event_channel, tx_num_wr, vlan, false),
		  m_p_wq(NULL), m_p_wq_family(NULL), m_p_rwq_ind_tbl(NULL),
		  m_buff_data(buff_d), m_external_mem(external_mem) {
		m_p_mp_ring = p_ring;
		m_n_sysvar_rx_num_wr_to_post_recv = m_p_mp_ring->get_wq_count();
		if (configure(p_rx_comp_event_channel))
			throw_vma_exception("failed creating mp qp");
	};
	bool 		fill_hw_descriptors(vma_mlx_hw_device_data &data);
	virtual		~qp_mgr_mp();
	virtual void	up();
	int		post_recv(uint32_t sg_index, uint32_t num_of_sge);
	int		get_wq_count() {return m_p_mp_ring->get_wq_count();}
	ibv_exp_wq*	get_wq() {return m_p_wq;}
protected:
	virtual cq_mgr* init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual int	prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr);
private:
	// override parent ring
	const ring_eth_cb*		m_p_mp_ring;
	struct ibv_exp_wq*		m_p_wq;
	struct ibv_exp_wq_family*	m_p_wq_family;
	struct ibv_exp_rwq_ind_table*	m_p_rwq_ind_tbl;
	ibv_sge				m_buff_data;
	bool				m_external_mem;
};
#endif /* HAVE_MP_RQ */

#endif /* SRC_VMA_DEV_QP_MGR_MP_H_ */
