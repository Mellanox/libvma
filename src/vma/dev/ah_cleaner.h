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


#ifndef AH_CLEANER_H
#define AH_CLEANER_H

#include <netinet/in.h>
#include "vma/proto/mem_buf_desc.h"

class mem_buf_desc_t;
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


