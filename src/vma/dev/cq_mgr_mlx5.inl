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
