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

#ifndef DM_CONTEXT_H
#define DM_CONTEXT_H

#include "vma/util/vma_stats.h"
#include "vma/util/verbs_extra.h"

class mem_buf_desc_t;
class ib_ctx_handler;

#if defined(HAVE_INFINIBAND_MLX5_HW_H)
#if defined(HAVE_IBV_DM)

#define DM_COMPLIATION_THRESHOLD 8192

struct vma_mlx5_dm {
	struct ibv_dm  ibv_dm;
	size_t         length;
	char           *start_va;
};

class dm_context {
public:

	dm_context();
	bool          dm_allocate_resources(ib_ctx_handler* ib_ctx, ring_stats_t* ring_stats);
	void          dm_release_resources();
	bool          dm_copy_data(struct mlx5_wqe_data_seg* seg, uint8_t* src, uint32_t length, mem_buf_desc_t* buff);
	void          dm_release_data(mem_buf_desc_t* buff);
	inline bool   dm_is_compilation_need() { return m_allocation - m_used < DM_COMPLIATION_THRESHOLD; };

private:

	struct ibv_mr  *m_p_dm_mr;
	vma_mlx5_dm    *m_p_mlx5_dm;
	ring_stats_t   *m_p_ring_stat;
	size_t         m_allocation;         // Size of device memory buffer (bytes)
	size_t         m_used;               // Next available index inside the buffer
	size_t         m_head;               // Device memory used bytes
};

#else

class dm_context {
public:
	inline bool   dm_allocate_resources(ib_ctx_handler* ib_ctx, ring_stats_t* ring_stats) { NOT_IN_USE(ib_ctx); NOT_IN_USE(ring_stats); return false; };
	inline void   dm_release_resources() {};
	inline bool   dm_copy_data(struct mlx5_wqe_data_seg* seg, uint8_t* src, uint32_t length, mem_buf_desc_t* buff) { NOT_IN_USE(seg); NOT_IN_USE(src); NOT_IN_USE(length); NOT_IN_USE(buff); return false; };
	inline void   dm_release_data(mem_buf_desc_t* buff) { NOT_IN_USE(buff); };
	inline bool   dm_is_compilation_need() { return false; };
};

#endif /* HAVE_IBV_DM */
#endif /* HAVE_INFINIBAND_MLX5_HW_H */
#endif /* DM_CONTEXT_H */
