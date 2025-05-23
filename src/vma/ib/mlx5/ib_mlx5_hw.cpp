/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "util/valgrind.h"
#if defined(DEFINED_DIRECT_VERBS) && (DEFINED_DIRECT_VERBS == 2)

#include "vma/ib/mlx5/ib_mlx5.h"

static int vma_ib_mlx5dv_get_qp(struct ibv_qp *qp, struct mlx5dv_qp *mlx5_qp);
static int vma_ib_mlx5dv_get_cq(struct ibv_cq *cq, struct mlx5dv_cq *mlx5_cq);


int vma_ib_mlx5dv_init_obj(struct mlx5dv_obj *obj, uint64_t obj_type)
{
	int ret = 0;

	if (obj_type & MLX5DV_OBJ_QP) {
		ret = vma_ib_mlx5dv_get_qp(obj->qp.in, obj->qp.out);
	}

	if (!ret && (obj_type & MLX5DV_OBJ_CQ)) {
		ret = vma_ib_mlx5dv_get_cq(obj->cq.in, obj->cq.out);
	}

	return ret;
}

static int vma_ib_mlx5dv_get_qp(struct ibv_qp *qp, struct mlx5dv_qp *mlx5_qp)
{
	int ret = 0;
	struct ibv_mlx5_qp_info ibv_qp_info;
	struct mlx5_qp *mqp = to_mqp(qp);

	ret = ibv_mlx5_exp_get_qp_info(qp, &ibv_qp_info);
	if (ret != 0) {
		return ret;
	}
	VALGRIND_MAKE_MEM_DEFINED(&ibv_qp_info, sizeof(ibv_qp_info));
	mlx5_qp->dbrec      = ibv_qp_info.dbrec;
	mlx5_qp->sq.buf     = (mqp->sq_buf_size ?
			(void *)((uintptr_t)mqp->sq_buf.buf) : /* IBV_QPT_RAW_PACKET or Underly QP */
			(void *)((uintptr_t)mqp->buf.buf + mqp->sq.offset));
	mlx5_qp->sq.wqe_cnt = ibv_qp_info.sq.wqe_cnt;
	mlx5_qp->sq.stride  = ibv_qp_info.sq.stride;
	mlx5_qp->rq.buf     = ibv_qp_info.rq.buf;
	mlx5_qp->rq.wqe_cnt = ibv_qp_info.rq.wqe_cnt;
	mlx5_qp->rq.stride  = ibv_qp_info.rq.stride;
	mlx5_qp->bf.reg     = ibv_qp_info.bf.reg;
	mlx5_qp->bf.size    = ibv_qp_info.bf.size;

	return ret;
}

static int vma_ib_mlx5dv_get_cq(struct ibv_cq *cq, struct mlx5dv_cq *mlx5_cq)
{
	int ret = 0;
	struct ibv_mlx5_cq_info ibv_cq_info;

	ret = ibv_mlx5_exp_get_cq_info(cq, &ibv_cq_info);
	if (ret != 0) {
		return ret;
	}
	VALGRIND_MAKE_MEM_DEFINED(&ibv_cq_info, sizeof(ibv_cq_info));
	mlx5_cq->buf      = ibv_cq_info.buf;
	mlx5_cq->dbrec    = ibv_cq_info.dbrec;
	mlx5_cq->cqe_cnt  = ibv_cq_info.cqe_cnt;
	mlx5_cq->cqe_size = ibv_cq_info.cqe_size;
	mlx5_cq->cq_uar   = NULL;
	mlx5_cq->cqn      = ibv_cq_info.cqn;

	return ret;
}

int vma_ib_mlx5_req_notify_cq(vma_ib_mlx5_cq_t *mlx5_cq, int solicited)
{
	struct mlx5_cq *mcq = to_mcq(mlx5_cq->cq);
 	mcq->cons_index = mlx5_cq->cq_ci;
	return ibv_req_notify_cq(mlx5_cq->cq, solicited);
}

void vma_ib_mlx5_get_cq_event(vma_ib_mlx5_cq_t *, int)
{
	// no need in operation with cq_sn as far as it is managed by driver code for now
}

#endif /* (DEFINED_DIRECT_VERBS == 2) */
