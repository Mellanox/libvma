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


#ifndef IB_CTX_HANDLER_COLLECTION_H
#define IB_CTX_HANDLER_COLLECTION_H

#include <unordered_map>

#include "vma/ib/base/verbs_extra.h"
#include "ib_ctx_handler.h"

typedef std::unordered_map<struct ibv_device*, ib_ctx_handler*>  ib_context_map_t;

class ib_ctx_handler_collection
{
public:
	ib_ctx_handler_collection();
	~ib_ctx_handler_collection();

	void update_tbl(const char *ifa_name = NULL);
	void print_val_tbl();

	inline ib_context_map_t* get_ib_cxt_list() {
		return (m_ib_ctx_map.size() ? &m_ib_ctx_map : NULL);
	}
	ib_ctx_handler* get_ib_ctx(const char *ifa_name);
	void del_ib_ctx(ib_ctx_handler* ib_ctx);

private:
	ib_context_map_t	m_ib_ctx_map;
};

extern ib_ctx_handler_collection* g_p_ib_ctx_handler_collection;

#endif
