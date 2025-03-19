/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef CQ_MGR_MLX5_INL_H
#define CQ_MGR_MLX5_INL_H

#include "dev/cq_mgr_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/
inline struct mlx5_cqe64* cq_mgr_mlx5::check_cqe(void)
{
	struct mlx5_cqe64* cqe = (struct mlx5_cqe64 *)(((uint8_t *)m_mlx5_cq.cq_buf) +
			((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));
	/*
	 * CQE ownership is defined by Owner bit in the CQE.
	 * The value indicating SW ownership is flipped every
	 *  time CQ wraps around.
	 * */
	if (likely((MLX5_CQE_OPCODE(cqe->op_own)) != MLX5_CQE_INVALID) &&
	    !((MLX5_CQE_OWNER(cqe->op_own)) ^ !!(m_mlx5_cq.cq_ci & m_mlx5_cq.cqe_count))) {
		return cqe;
	}

	return NULL;
}

#endif /* DEFINED_DIRECT_VERBS */
#endif//CQ_MGR_MLX5_INL_H
