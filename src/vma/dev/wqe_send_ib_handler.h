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
#include "vma/util/vtypes.h"

#ifndef WQE_TEMPLATE_SEND_IB_H_
#define WQE_TEMPLATE_SEND_IB_H_

class wqe_send_ib_handler: public wqe_send_handler
{
public:
	wqe_send_ib_handler();
	virtual ~wqe_send_ib_handler();

	void init_ib_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge, struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);
	void init_inline_ib_wqe(vma_ibv_send_wr & wqe_to_init, struct ibv_sge *sge_list, uint32_t num_sge, struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);
	void init_not_inline_ib_wqe(vma_ibv_send_wr & wqe_to_init, struct ibv_sge *sge_list, uint32_t num_sge, struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);

private:
    void init_path_record(vma_ibv_send_wr & wqe_to_init, struct ibv_ah *ah, uint32_t rem_qkey, uint32_t rem_qpn);
};

#endif /* WQE_TEMPLATE_SEND_IB_H_ */
