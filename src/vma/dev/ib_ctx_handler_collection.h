/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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

typedef std::tr1::unordered_map<struct ibv_device*, ib_ctx_handler*>  ib_context_map_t;

class ib_ctx_handler_collection
{
public:
	ib_ctx_handler_collection();
	~ib_ctx_handler_collection();

	inline ib_context_map_t* get_ib_cxt_list() {
		return (m_ib_ctx_map.size() ? &m_ib_ctx_map : NULL);
	}
	ib_ctx_handler* get_ib_ctx(const char *ifa_name);
	void del_ib_ctx(ib_ctx_handler* ib_ctx);

	inline size_t get_num_devices() {
		return m_ib_ctx_map.size();
	};
	inline ts_conversion_mode_t get_ctx_time_conversion_mode() {
		return m_ctx_time_conversion_mode;
	};

private:
	void update_tbl();
	void print_val_tbl();

	ib_context_map_t	m_ib_ctx_map;
	ts_conversion_mode_t m_ctx_time_conversion_mode;
};

extern ib_ctx_handler_collection* g_p_ib_ctx_handler_collection;

#endif
