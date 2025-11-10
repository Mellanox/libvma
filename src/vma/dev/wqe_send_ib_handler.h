/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "wqe_send_handler.h"
#include "vma/util/vtypes.h"

#ifndef WQE_TEMPLATE_SEND_IB_H_
#define WQE_TEMPLATE_SEND_IB_H_

class wqe_send_ib_handler: public wqe_send_handler
{
public:
	wqe_send_ib_handler();
	virtual ~wqe_send_ib_handler();

	void init_ib_wqe(ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge, struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);
	void init_inline_ib_wqe(ibv_send_wr & wqe_to_init, struct ibv_sge *sge_list, uint32_t num_sge, struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);
	void init_not_inline_ib_wqe(ibv_send_wr & wqe_to_init, struct ibv_sge *sge_list, uint32_t num_sge, struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);

private:
    void init_path_record(ibv_send_wr & wqe_to_init, struct ibv_ah *ah, uint32_t rem_qkey, uint32_t rem_qpn);
};

#endif /* WQE_TEMPLATE_SEND_IB_H_ */
