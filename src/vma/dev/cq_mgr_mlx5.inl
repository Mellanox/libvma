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


#ifndef CQ_MGR_MLX5_INL_H
#define CQ_MGR_MLX5_INL_H

#include "dev/cq_mgr_mlx5.h"

#ifdef HAVE_INFINIBAND_MLX5_HW_H

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/
inline volatile struct mlx5_cqe64* cq_mgr_mlx5::check_cqe(void)
{
	volatile struct mlx5_cqe64 *cqe = &(*m_cqes)[m_cq_cons_index & (m_cq_size - 1)];

	/*
	 * CQE ownership is defined by Owner bit in the CQE.
	 * The value indicating SW ownership is flipped every
	 *  time CQ wraps around.
	 * */
	if (likely((MLX5_CQE_OPCODE(cqe->op_own)) != MLX5_CQE_INVALID) &&
	    !((MLX5_CQE_OWNER(cqe->op_own)) ^ !!(m_cq_cons_index & m_cq_size))) {
		++m_cq_cons_index;
		wmb();
		++m_rq->tail;
		*m_cq_dbell = htonl(m_cq_cons_index & 0xffffff);
		return cqe;
	}

	return NULL;
}

#endif //HAVE_INFINIBAND_MLX5_HW_H
#endif//CQ_MGR_MLX5_INL_H
