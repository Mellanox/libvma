/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef SRC_VMA_DEV_QP_MGR_ETH_DIRECT_H_
#define SRC_VMA_DEV_QP_MGR_ETH_DIRECT_H_

#include "qp_mgr_eth_mlx5.h"

class qp_mgr_eth_direct: public qp_mgr_eth_mlx5
{
public:
	qp_mgr_eth_direct(struct qp_mgr_desc *desc,
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

#endif /* SRC_VMA_DEV_QP_MGR_ETH_DIRECT_H_ */
