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

private:
	ib_context_map_t        m_ib_ctx_map;
	int                     m_n_num_devices;
};

extern ib_ctx_handler_collection* g_p_ib_ctx_handler_collection;

#endif
