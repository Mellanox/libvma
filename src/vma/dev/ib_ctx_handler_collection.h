/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
