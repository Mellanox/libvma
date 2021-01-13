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
