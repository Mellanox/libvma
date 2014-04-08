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


#include "vlogger/vlogger.h"
#include "vma/util/verbs_extra.h"
#include "ib_ctx_handler_collection.h"
#include "vma/util/bullseye.h"

#define MODULE_NAME             "ib_ctx_collection"


#define ibchc_logpanic           __log_panic
#define ibchc_logerr             __log_err
#define ibchc_logwarn            __log_warn
#define ibchc_loginfo            __log_info
#define ibchc_logdbg             __log_info_dbg
#define ibchc_logfunc            __log_info_func
#define ibchc_logfuncall         __log_info_funcall

ib_ctx_handler_collection* g_p_ib_ctx_handler_collection = NULL;


ib_ctx_handler_collection::ib_ctx_handler_collection() : m_n_num_devices(0)
{
}

ib_ctx_handler_collection::~ib_ctx_handler_collection()
{
	ib_context_map_t::iterator ib_ctx_iter;
	while ((ib_ctx_iter = m_ib_ctx_map.begin()) != m_ib_ctx_map.end()) {
		ib_ctx_handler* p_ib_ctx_handler = ib_ctx_iter->second;
		delete p_ib_ctx_handler;
		m_ib_ctx_map.erase(ib_ctx_iter);
	}
}

void ib_ctx_handler_collection::map_ib_devices() //return num_devices, can use rdma_get_devices()
{
	struct ibv_context** pp_ibv_context_list = rdma_get_devices(&m_n_num_devices);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!pp_ibv_context_list) {
		ibchc_logwarn("Failure in rdma_get_devices() (error=%d %m)", errno);
		ibchc_logpanic("Please check OFED installation");
	}
	if (!m_n_num_devices) {
		rdma_free_devices(pp_ibv_context_list);
		ibchc_logpanic("No RDMA capable devices found!");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	ibchc_logdbg("Mapping %d ibv devices", m_n_num_devices);
	for (int i = 0; i < m_n_num_devices; i++) {
		m_ib_ctx_map[pp_ibv_context_list[i]] = new ib_ctx_handler(pp_ibv_context_list[i]);
	}

	rdma_free_devices(pp_ibv_context_list);
}

ib_ctx_handler* ib_ctx_handler_collection::get_ib_ctx(struct ibv_context* p_ibv_context)
{
	if (m_ib_ctx_map.count(p_ibv_context) > 0)
		return m_ib_ctx_map[p_ibv_context];
	return NULL;
}

size_t ib_ctx_handler_collection::mem_reg_on_all_devices(void* addr, size_t length, 
                                                  ibv_mr** mr_array, size_t mr_array_sz,
                                                  uint64_t access)
{
	ibchc_logfunc("");
	size_t mr_pos = 0;
	ib_context_map_t::iterator ib_ctx_iter;
	for (ib_ctx_iter = m_ib_ctx_map.begin(); ib_ctx_iter != m_ib_ctx_map.end(), mr_pos<mr_array_sz; ib_ctx_iter++, mr_pos++) {
		ib_ctx_handler* p_ib_ctx_handler = ib_ctx_iter->second;
		mr_array[mr_pos] = p_ib_ctx_handler->mem_reg(addr, length, access);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (mr_array[mr_pos] == NULL) {
			ibchc_logwarn("Failure in mem_reg: addr=%p, length=%d, mr_pos=%d, mr_array[mr_pos]=%d, dev=%p, ibv_dev=%s", 
				    addr, length, mr_pos, mr_array[mr_pos], p_ib_ctx_handler, p_ib_ctx_handler->get_ibv_device()->name);
			return (size_t)-1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		errno = 0; //ibv_reg_mr() set errno=12 despite successful returning
#ifdef VMA_IBV_ACCESS_ALLOCATE_MR
		if ((access & VMA_IBV_ACCESS_ALLOCATE_MR) != 0) { // contig pages mode
			// When using 'IBV_ACCESS_ALLOCATE_MR', ibv_reg_mr will return a pointer that its 'addr' field will hold the address of the allocated memory.
			// Second registration and above is done using 'IBV_ACCESS_LOCAL_WRITE' and the 'addr' we received from the first registration.
			addr = mr_array[0]->addr;
			access &= ~VMA_IBV_ACCESS_ALLOCATE_MR;
		}
#endif

		ibchc_logdbg("addr=%p, length=%d, pos=%d, mr[pos]->lkey=%u, dev1=%p, dev2=%p",
			   addr, length, mr_pos, mr_array[mr_pos]->lkey, mr_array[mr_pos]->context->device, p_ib_ctx_handler->get_ibv_device());
	}
	return mr_pos;
}
