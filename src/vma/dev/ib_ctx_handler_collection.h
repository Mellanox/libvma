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


#ifndef IB_CTX_HANDLER_COLLECTION_H
#define IB_CTX_HANDLER_COLLECTION_H

#include <tr1/unordered_map>

#include "vma/util/verbs_extra.h"
#include "ib_ctx_handler.h"

typedef std::tr1::unordered_map<struct ibv_context*, ib_ctx_handler*>  ib_context_map_t;

class ib_ctx_handler_collection
{
public:
	ib_ctx_handler_collection();
	~ib_ctx_handler_collection();
	void            map_ib_devices(); //return num_devices, can use rdma_get_devices()
	ib_ctx_handler* get_ib_ctx(struct ibv_context*);
	size_t		get_num_devices() {return m_n_num_devices; };
	size_t          mem_reg_on_all_devices(void* addr, size_t length,
			ibv_mr** mr_array, size_t mr_array_sz,
			uint64_t access);
	ts_conversion_mode_t    get_ctx_time_conversion_mode();

private:
	ib_context_map_t	m_ib_ctx_map;
	int			m_n_num_devices;
	ts_conversion_mode_t    m_ctx_time_conversion_mode;
	void			free_ibchc_resources(void);
};

extern ib_ctx_handler_collection* g_p_ib_ctx_handler_collection;

#endif
