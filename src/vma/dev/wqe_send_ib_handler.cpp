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

void wqe_send_ib_handler::init_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge,
		    struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey)
{
	wqe_send_handler::init_wqe(wqe_to_init, sge_list, num_sge);
	init_path_record(wqe_to_init, ah, rem_qkey, rem_qpn);
}

void wqe_send_ib_handler::init_inline_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge,
		    struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey)
{
	wqe_send_handler::init_inline_wqe(wqe_to_init, sge_list, num_sge);
	init_path_record(wqe_to_init, ah, rem_qkey, rem_qpn);
}

//code coverage
#if 0
void wqe_send_ib_handler::enable_imm_data(vma_ibv_send_wr &send_wqe)
{
	send_wqe.opcode = IBV_WR_SEND_WITH_IMM;
	send_wqe.imm_data = MCE_IMM_DATA_MASK_MC_TX_LOOP_DISABLED;
}

void wqe_send_ib_handler::disable_imm_data(vma_ibv_send_wr &send_wqe)
{
	send_wqe.opcode = IBV_WR_SEND;
	send_wqe.imm_data = 0;
}
#endif
