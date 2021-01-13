/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#include "wqe_send_handler.h"

wqe_send_handler::wqe_send_handler()
{
}

wqe_send_handler::~wqe_send_handler()
{
}

void wqe_send_handler::init_inline_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	init_not_inline_wqe(wqe_to_init, sge_list, num_sge);
	enable_inline(wqe_to_init);
}

void wqe_send_handler::init_not_inline_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	init_wqe(wqe_to_init, sge_list, num_sge);
	enable_hw_csum(wqe_to_init);
}

void wqe_send_handler::init_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge)
{
	memset(&wqe_to_init, 0, sizeof(wqe_to_init));

	wqe_to_init.num_sge = num_sge;
	vma_send_wr_opcode(wqe_to_init) = VMA_IBV_WR_SEND;
	wqe_to_init.next = NULL;
	wqe_to_init.sg_list = sge_list;
	wqe_to_init.wr_id = 0;
}
