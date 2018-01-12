/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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


class vma_allocator {
public:
	vma_allocator();
	~vma_allocator();
	void* alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h);
	void* get_ptr() const {return m_data_block;}
	uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;
	ibv_mr* find_ibv_mr_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;
private:
	bool register_memory(size_t size, ib_ctx_handler *p_ib_ctx_h, uint64_t access);
	bool hugetlb_alloc(size_t sz_bytes);
	// List of memory regions
	ibv_mr** m_mr_list;
	size_t m_mr_list_len;
	int m_shmid;
	void *m_data_block;
	bool m_is_contig_alloc;
	uint64_t m_contig_access_mr;
	uint64_t m_non_contig_access_mr;
};

#endif /* SRC_VMA_DEV_ALLOCATOR_H_ */
