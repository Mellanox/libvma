/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "vma/ib/base/verbs_extra.h"
#include "vma/util/to_str.h"

#ifndef IB_WQE_TEMPLATE_H
#define IB_WQE_TEMPLATE_H

class wqe_send_handler: public tostr
{
public:
	wqe_send_handler();
	virtual ~wqe_send_handler();

	void init_wqe(ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge);
	void init_inline_wqe(ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge);
	void init_not_inline_wqe(ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge);

	inline ibv_wr_opcode set_opcode(ibv_send_wr &wqe, ibv_wr_opcode opcode) {
		ibv_wr_opcode last_opcode = vma_send_wr_opcode(wqe);
		vma_send_wr_opcode(wqe) = opcode;
		return last_opcode;
	}

#ifndef DEFINED_SW_CSUM
	inline void  enable_hw_csum (ibv_send_wr &send_wqe) { vma_send_wr_send_flags(send_wqe) |= IBV_SEND_IP_CSUM; }
	inline void disable_hw_csum (ibv_send_wr &send_wqe) { vma_send_wr_send_flags(send_wqe) &= ~IBV_SEND_IP_CSUM; }
#else
	inline void  enable_hw_csum (ibv_send_wr &) {}
	inline void disable_hw_csum (ibv_send_wr &) {}
#endif

	inline void enable_inline (ibv_send_wr &send_wqe) { vma_send_wr_send_flags(send_wqe) |= IBV_SEND_INLINE; }
};

#endif /* IB_WQE_TEMPLATE_H */
