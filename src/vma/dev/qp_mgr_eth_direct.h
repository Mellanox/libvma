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
#ifndef SRC_VMA_DEV_QP_MGR_ETH_DIRECT_H_
#define SRC_VMA_DEV_QP_MGR_ETH_DIRECT_H_

#include "qp_mgr_eth_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)

class qp_mgr_eth_direct: public qp_mgr_eth_mlx5
{
public:
	qp_mgr_eth_direct(const ring_simple* p_ring, const ib_ctx_handler* p_context,
			  const uint8_t port_num, ibv_comp_channel* p_rx_comp_event_channel,
			  const uint32_t tx_num_wr, const uint16_t vlan);
	virtual ~qp_mgr_eth_direct();
	virtual cq_mgr*		init_tx_cq_mgr(void);
	virtual void		up();
	virtual void		down();
	virtual uint32_t	get_rx_max_wr_num() { return 0;};
	virtual bool		fill_hw_descriptors(vma_mlx_hw_device_data &data);
protected:
	virtual int		prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr);
};

#endif /* DEFINED_DIRECT_VERBS */

#endif /* SRC_VMA_DEV_QP_MGR_ETH_DIRECT_H_ */
