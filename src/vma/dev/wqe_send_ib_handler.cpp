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
