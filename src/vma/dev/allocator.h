/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef SRC_VMA_DEV_ALLOCATOR_H_
#define SRC_VMA_DEV_ALLOCATOR_H_

#include "vlogger/vlogger.h"
#include "ib_ctx_handler_collection.h"


class ib_ctx_handler;
typedef std::tr1::unordered_map<ib_ctx_handler*, uint32_t> lkey_map_ib_ctx_map_t;

class vma_allocator {
public:
	vma_allocator();
	~vma_allocator();
	void* alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h, void *ptr = NULL);
	uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;
	ibv_mr* find_ibv_mr_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;
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
};

#endif /* SRC_VMA_DEV_ALLOCATOR_H_ */
