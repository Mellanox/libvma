/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef DM_MGR_H
#define DM_MGR_H

#include "vma/ib/base/verbs_extra.h"
#include "vma/util/vma_stats.h"

class mem_buf_desc_t;
class ib_ctx_handler;

#if defined(DEFINED_DIRECT_VERBS)
#if defined(DEFINED_IBV_DM)

#define DM_COMPLETION_THRESHOLD 8192

class dm_mgr {
public:

	dm_mgr();
	bool          allocate_resources(ib_ctx_handler* ib_ctx, ring_stats_t* ring_stats);
	void          release_resources();
	bool          copy_data(struct mlx5_wqe_data_seg* seg, uint8_t* src, uint32_t length, mem_buf_desc_t* buff);
	void          release_data(mem_buf_desc_t* buff);
	inline bool   is_completion_need() { return m_allocation - m_used < DM_COMPLETION_THRESHOLD; };

private:

	struct ibv_mr  *m_p_dm_mr;
	vma_ibv_dm     *m_p_ibv_dm;
	ring_stats_t   *m_p_ring_stat;
	size_t         m_allocation;         // Size of device memory buffer (bytes)
	size_t         m_used;               // Next available index inside the buffer
	size_t         m_head;               // Device memory used bytes
};

#else

/* cppcheck-suppress ctuOneDefinitionRuleViolation */
class dm_mgr {
public:
	inline bool   allocate_resources(ib_ctx_handler* ib_ctx, ring_stats_t* ring_stats) { NOT_IN_USE(ib_ctx); NOT_IN_USE(ring_stats); return false; };
	inline void   release_resources() {};
	inline bool   copy_data(struct mlx5_wqe_data_seg* seg, uint8_t* src, uint32_t length, mem_buf_desc_t* buff) { NOT_IN_USE(seg); NOT_IN_USE(src); NOT_IN_USE(length); NOT_IN_USE(buff); return false; };
	inline void   release_data(mem_buf_desc_t* buff) { NOT_IN_USE(buff); };
	inline bool   is_completion_need() { return false; };
};

#endif /* DEFINED_IBV_DM */
#endif /* DEFINED_DIRECT_VERBS */
#endif /* DM_MGR_H */
