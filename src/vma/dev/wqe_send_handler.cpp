/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#include "wqe_send_handler.h"

wqe_send_handler::wqe_send_handler()
{
}

wqe_send_handler::~wqe_send_handler()
{
}

void wqe_send_handler::init_inline_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	memset(&wqe_to_init, 0, sizeof(vma_ibv_send_wr));

	wqe_to_init.num_sge = num_sge;
	vma_send_wr_opcode(wqe_to_init) = VMA_IBV_WR_SEND;
	wqe_to_init.next = NULL;
	wqe_to_init.sg_list = sge_list;
	wqe_to_init.wr_id = 0;
	enable_hw_csum(wqe_to_init);
	enable_inline(wqe_to_init);
}

void wqe_send_handler::init_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	memset(&wqe_to_init, 0, sizeof(vma_ibv_send_wr));

	wqe_to_init.num_sge = num_sge;
	vma_send_wr_opcode(wqe_to_init) = VMA_IBV_WR_SEND;
	wqe_to_init.next = NULL;
	wqe_to_init.sg_list = sge_list;
	wqe_to_init.wr_id = 0;
}
