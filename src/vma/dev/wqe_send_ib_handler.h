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

/*
 * wqe_handler_send_ib.h
 *
 *  Created on: Jul 15, 2012
 *      Author: alexv
 */

#include "wqe_send_handler.h"
#include "util/vtypes.h"

#ifndef WQE_TEMPLATE_SEND_IB_H_
#define WQE_TEMPLATE_SEND_IB_H_

class wqe_send_ib_handler: public wqe_send_handler
{
public:
	wqe_send_ib_handler();
	virtual ~wqe_send_ib_handler();


	virtual void init_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge,
			     struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);
	virtual void init_inline_wqe(vma_ibv_send_wr & wqe_to_init, struct ibv_sge *sge_list, uint32_t num_sge, struct ibv_ah *ah, uint32_t rem_qpn, uint32_t rem_qkey);
	void enable_imm_data(vma_ibv_send_wr &send_wqe);
	void disable_imm_data(vma_ibv_send_wr &send_wqe);

private:
    void init_path_record(vma_ibv_send_wr & wqe_to_init, struct ibv_ah *ah, uint32_t rem_qkey, uint32_t rem_qpn);
};

#endif /* WQE_TEMPLATE_SEND_IB_H_ */
