/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "wqe_send_ib_handler.h"

wqe_send_ib_handler::wqe_send_ib_handler()
{
}

wqe_send_ib_handler::~wqe_send_ib_handler()
{
}

void wqe_send_ib_handler::init_path_record(vma_ibv_send_wr &wqe_to_init, struct ibv_ah *ah, uint32_t rem_qkey, uint32_t rem_qpn)
{
	wqe_to_init.wr.ud.ah = ah;
	wqe_to_init.wr.ud.remote_qkey = rem_qkey;
	wqe_to_init.wr.ud.remote_qpn = rem_qpn;
}

void wqe_send_ib_handler::init_ib_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge,
		    struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey)
{
	wqe_send_handler::init_wqe(wqe_to_init, sge_list, num_sge);
	init_path_record(wqe_to_init, ah, rem_qkey, rem_qpn);
}

void wqe_send_ib_handler::init_inline_ib_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge,
		    struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey)
{
	wqe_send_handler::init_inline_wqe(wqe_to_init, sge_list, num_sge);
	init_path_record(wqe_to_init, ah, rem_qkey, rem_qpn);
}

void wqe_send_ib_handler::init_not_inline_ib_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge,
		    struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey)
{
	wqe_send_handler::init_not_inline_wqe(wqe_to_init, sge_list, num_sge);
	init_path_record(wqe_to_init, ah, rem_qkey, rem_qpn);
}
