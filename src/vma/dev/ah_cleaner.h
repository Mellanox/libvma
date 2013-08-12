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


#ifndef AH_CLEANER_H
#define AH_CLEANER_H

#include <netinet/in.h>
#include "vma/proto/mem_buf_desc.h"
#include "qp_mgr.h"

struct mem_buf_desc_t;
class ring;

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

class ah_cleaner: public mem_buf_desc_owner
{
public:
	ah_cleaner(struct ibv_ah* ah, ring* p_ring);

	// Call back function
	virtual void		mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_rx_wc_buf_desc);
	virtual void		mem_buf_desc_completion_with_error_rx(mem_buf_desc_t*) {} // ah is relevant only in TX flow
	virtual void		mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual void		mem_buf_desc_return_to_owner_rx(mem_buf_desc_t*, void*){} // ah is relevant only in RX flow
	mem_buf_desc_owner*	m_next_owner;

private:
	void			destroy_ah_n_return_to_owner(mem_buf_desc_t* p_mem_buf_desc);
	struct ibv_ah*		m_ah;
	ring*			m_p_ring;
};

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

#endif


