/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SRC_VMA_IB_MLX5_HW_H_
#define SRC_VMA_IB_MLX5_HW_H_

#ifndef SRC_VMA_IB_MLX5_H_
#error "Use <vma/ib/mlx5/ib_mlx5.h> instead."
#endif

#if defined(DEFINED_DIRECT_VERBS) && (DEFINED_DIRECT_VERBS == 2)

#include <stdint.h>

/* This structures duplicate mlx5dv.h (rdma-core upstream)
 * to use upstream specific approach as a basis
 */
struct mlx5dv_qp {
	volatile uint32_t *dbrec;
	struct {
		void *buf;
		uint32_t wqe_cnt;
		uint32_t stride;
	} sq;
	struct {
		void *buf;
		uint32_t wqe_cnt;
		uint32_t stride;
	} rq;
	struct {
		void *reg;
		uint32_t size;
	} bf;
	uint64_t comp_mask;
};

struct mlx5dv_cq {
	void *buf;
	volatile uint32_t *dbrec;
	uint32_t cqe_cnt;
	uint32_t cqe_size;
	void *cq_uar;
	uint32_t cqn;
	uint64_t comp_mask;
};

struct mlx5dv_obj {
	struct {
		struct ibv_qp *in;
		struct mlx5dv_qp *out;
	} qp;
	struct {
		struct ibv_cq *in;
		struct mlx5dv_cq *out;
	} cq;
};

enum mlx5dv_obj_type {
	MLX5DV_OBJ_QP = 1 << 0,
	MLX5DV_OBJ_CQ = 1 << 1,
};

#endif /* (DEFINED_DIRECT_VERBS == 2) */

#endif /* SRC_VMA_IB_MLX5_HW_H_ */
