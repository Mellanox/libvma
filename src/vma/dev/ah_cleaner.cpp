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



#include "vma/util/verbs_extra.h"
#include "ring.h"
#include "ah_cleaner.h"

#define MODULE_NAME 		"ahc:"

#define ach_logerr		__log_info_err
#define ach_logdbg		__log_info_dbg

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

ah_cleaner::ah_cleaner(struct ibv_ah* ah, ring* p_ring) : m_ah(ah), m_p_ring(p_ring)
{
	ach_logdbg("ah_cleaner created [ah=%p, ring=%p]", ah, p_ring);
	m_next_owner = NULL;
}

// Arriving This function means that we got completion about our closing ah tx packet,
// so we can destroy the old address_handler
//
void ah_cleaner::mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_rx_wc_buf_desc)
{
	destroy_ah_n_return_to_owner(p_rx_wc_buf_desc);
}

void ah_cleaner::mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_rx_wc_buf_desc)
{
	destroy_ah_n_return_to_owner(p_rx_wc_buf_desc);
}

void ah_cleaner::destroy_ah_n_return_to_owner(mem_buf_desc_t* p_mem_buf_desc)
{
	if (m_next_owner) {
		p_mem_buf_desc->p_desc_owner = m_p_ring;
		m_next_owner->mem_buf_desc_return_to_owner_tx(p_mem_buf_desc);
	}
	else {
		ach_logerr("no desc_owner!");
	}

	ach_logdbg("destroy ah %p", m_ah);
	IF_VERBS_FAILURE(ibv_destroy_ah(m_ah)) {
		ach_logerr("failed destroying address handle (errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;
	delete this;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
