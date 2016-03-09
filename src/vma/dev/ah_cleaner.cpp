/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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
