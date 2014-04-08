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


#include "util/to_str.h"
#include "util/verbs_extra.h"
#include <string.h>

#ifndef IB_WQE_TEMPLATE_H
#define IB_WQE_TEMPLATE_H

class wqe_send_handler: public tostr
{
public:
	wqe_send_handler();
	virtual ~wqe_send_handler();

	virtual void init_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge);
	virtual void init_inline_wqe(vma_ibv_send_wr &wqe_to_init, struct ibv_sge* sge_list, uint32_t num_sge);

	inline void enable_hw_csum (vma_ibv_send_wr &send_wqe) { vma_send_wr_send_flags(send_wqe) |= VMA_IBV_SEND_IP_CSUM; };
	inline void disable_hw_csum (vma_ibv_send_wr &send_wqe) { vma_send_wr_send_flags(send_wqe) &= ~VMA_IBV_SEND_IP_CSUM; };
	inline void enable_inline (vma_ibv_send_wr &send_wqe) { vma_send_wr_send_flags(send_wqe) |= VMA_IBV_SEND_INLINE; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	inline void disable_inline (vma_ibv_send_wr &send_wqe) { vma_send_wr_send_flags(send_wqe) &= ~VMA_IBV_SEND_INLINE; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
};

#endif /* IB_WQE_TEMPLATE_H */
