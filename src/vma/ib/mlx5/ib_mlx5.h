/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef SRC_VMA_IB_MLX5_H_
#define SRC_VMA_IB_MLX5_H_

#include <infiniband/verbs.h>

#if defined(DEFINED_DIRECT_VERBS)
#if (DEFINED_DIRECT_VERBS == 2)
#include <infiniband/mlx5_hw.h>
#include "vma/ib/mlx5/ib_mlx5_hw.h"
#elif (DEFINED_DIRECT_VERBS == 3)
#include <infiniband/mlx5dv.h>
#include "vma/ib/mlx5/ib_mlx5_dv.h"
#else
#error "Unsupported Direct VERBS parameter"
#endif
#endif /* DEFINED_DIRECT_VERBS */

/* ib/mlx5 layer is used by other VMA code that needs
 * direct access to mlx5 resources.
 * It hides differences in rdma-core(Upstream OFED) and mlx5(Mellanox OFED) 
 * mlx5 provider implementations.
 * rdma-core(Upstream OFED) structures/macro/enum etc are taken as basis
 * inside this layer
 */


/**
 * Get internal verbs information.
 */
int vma_ib_mlx5dv_init_obj(struct mlx5dv_obj *obj, uint64_t type);

#endif /* SRC_VMA_IB_MLX5_H_ */
