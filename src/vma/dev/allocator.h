/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SRC_VMA_DEV_ALLOCATOR_H_
#define SRC_VMA_DEV_ALLOCATOR_H_

#include "vlogger/vlogger.h"
#include "ib_ctx_handler_collection.h"


class ib_ctx_handler;
typedef std::unordered_map<ib_ctx_handler*, uint32_t> lkey_map_ib_ctx_map_t;

class vma_allocator {
public:
	vma_allocator();
	vma_allocator(alloc_t alloc_func, free_t free_func);
	~vma_allocator();
	void* alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h, void *ptr = NULL);
	uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;
	void register_memory(size_t size, ib_ctx_handler *p_ib_ctx_h, uint64_t access);
	void deregister_memory();
private:
	void align_simple_malloc(size_t sz_bytes);
	bool hugetlb_alloc(size_t sz_bytes);
	bool hugetlb_mmap_alloc();
	bool hugetlb_sysv_alloc();
	lkey_map_ib_ctx_map_t m_lkey_map_ib_ctx;
	int m_shmid;
	size_t m_length;
	void *m_data_block;
	alloc_mode_t m_mem_alloc_type;
	alloc_t m_memalloc;
	free_t m_memfree;
};

#endif /* SRC_VMA_DEV_ALLOCATOR_H_ */
