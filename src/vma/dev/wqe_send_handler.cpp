/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "wqe_send_handler.h"

wqe_send_handler::wqe_send_handler()
{
}

wqe_send_handler::~wqe_send_handler()
{
}

void wqe_send_handler::init_inline_wqe(ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	init_not_inline_wqe(wqe_to_init, sge_list, num_sge);
	enable_inline(wqe_to_init);
}

void wqe_send_handler::init_not_inline_wqe(ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	init_wqe(wqe_to_init, sge_list, num_sge);
	enable_hw_csum(wqe_to_init);
}

void wqe_send_handler::init_wqe(ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	memset(&wqe_to_init, 0, sizeof(wqe_to_init));

	wqe_to_init.num_sge = num_sge;
	vma_send_wr_opcode(wqe_to_init) = IBV_WR_SEND;
	wqe_to_init.next = NULL;
	wqe_to_init.sg_list = sge_list;
	wqe_to_init.wr_id = 0;
}
