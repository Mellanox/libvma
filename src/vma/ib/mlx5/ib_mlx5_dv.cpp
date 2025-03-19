/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(DEFINED_DIRECT_VERBS) && (DEFINED_DIRECT_VERBS == 3)

#include "vma/ib/mlx5/ib_mlx5.h"

int vma_ib_mlx5dv_init_obj(struct mlx5dv_obj *obj, uint64_t type)
{
	int ret = 0;

	ret = mlx5dv_init_obj(obj, type);

	return ret;
}

int vma_ib_mlx5_req_notify_cq(vma_ib_mlx5_cq_t *mlx5_cq, int solicited)
{
	uint64_t doorbell;
	uint32_t sn;
	uint32_t ci;
	uint32_t cmd;

	sn  = mlx5_cq->cq_sn & 3;
	ci  = mlx5_cq->cq_ci & 0xffffff;
	cmd = solicited ? MLX5_CQ_DB_REQ_NOT_SOL : MLX5_CQ_DB_REQ_NOT;

	doorbell = sn << 28 | cmd | ci;
	doorbell <<= 32;
	doorbell |= mlx5_cq->cq_num;

	mlx5_cq->dbrec[VMA_IB_MLX5_CQ_ARM_DB] = htonl(sn << 28 | cmd | ci);

	/*
	 * Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI WC MMIO.
	 */
	wmb();

	*(uint64_t *)((uint8_t *)mlx5_cq->uar + MLX5_CQ_DOORBELL) = htonll(doorbell);

	wc_wmb();

	return 0;
}

void vma_ib_mlx5_get_cq_event(vma_ib_mlx5_cq_t *mlx5_cq, int count)
{
	mlx5_cq->cq_sn += count;
}

#endif /* (DEFINED_DIRECT_VERBS == 3) */
