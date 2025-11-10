/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SRC_VMA_IB_MLX5_H_
#define SRC_VMA_IB_MLX5_H_

#include <infiniband/verbs.h>
extern "C" {
#include <infiniband/mlx5dv.h>
}
#include <utils/asm.h>
#include <vma/util/vtypes.h>

/* ib/mlx5 layer is used by other VMA code that needs
 * direct access to mlx5 resources.
 * It hides differences in rdma-core(Upstream OFED) and mlx5(OFED)
 * mlx5 provider implementations.
 * rdma-core(Upstream OFED) structures/macro/enum etc are taken as basis
 * inside this layer
 */

enum {
   VMA_IB_MLX5_QP_FLAGS_USE_UNDERLAY = 0x01
};

enum {
	VMA_IB_MLX5_CQ_SET_CI    = 0,
	VMA_IB_MLX5_CQ_ARM_DB    = 1
};

/* Queue pair */
typedef struct vma_ib_mlx5_qp {
	struct ibv_qp *qp;
	uint32_t qpn;
	uint32_t flags;
	struct ibv_qp_cap cap;
	struct {
		volatile uint32_t *dbrec;
		void *buf;
		uint32_t wqe_cnt;
		uint32_t stride;
	} sq;
	struct {
		volatile uint32_t *dbrec;
		void *buf;
		uint32_t wqe_cnt;
		uint32_t stride;
		uint32_t wqe_shift;
		unsigned head;
		unsigned tail;
	} rq;
	struct {
		void *reg;
		uint32_t size;
		uint32_t offset;
	} bf;
} vma_ib_mlx5_qp_t;

/* Completion queue */
typedef struct vma_ib_mlx5_cq {
	struct ibv_cq      *cq;
	void               *cq_buf;
	unsigned           cq_num;
	unsigned           cq_ci;
	unsigned           cq_sn;
	unsigned           cqe_count;
	unsigned           cqe_size;
	unsigned           cqe_size_log;
	volatile uint32_t  *dbrec;
	void               *uar;
} vma_ib_mlx5_cq_t;

int vma_ib_mlx5_get_qp(struct ibv_qp *qp, vma_ib_mlx5_qp_t *mlx5_qp, uint32_t flags = 0);
int vma_ib_mlx5_post_recv(vma_ib_mlx5_qp_t *mlx5_qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr);

int vma_ib_mlx5_get_cq(struct ibv_cq *cq, vma_ib_mlx5_cq_t *mlx5_cq);
int vma_ib_mlx5_req_notify_cq(vma_ib_mlx5_cq_t *mlx5_cq, int solicited);
void vma_ib_mlx5_get_cq_event(vma_ib_mlx5_cq_t *mlx5_cq, int count);

#endif /* SRC_VMA_IB_MLX5_H_ */
