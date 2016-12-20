/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef WQE_H
#define WQE_H

#define MLX5_ETH_INLINE_HEADER_SIZE 16

#ifndef DEFINED_MLX5_HW_ETH_WQE_HEADER
enum {
	MLX5_ETH_WQE_L3_CSUM	=	(1 << 6),
	MLX5_ETH_WQE_L4_CSUM	=	(1 << 7),
};

struct mlx5_wqe_eth_seg {
	uint32_t        rsvd0;
	uint8_t         cs_flags;
	uint8_t         rsvd1;
	uint16_t        mss;
	uint32_t        rsvd2;
	uint16_t        inline_hdr_sz;
	uint8_t         inline_hdr_start[2];
	uint8_t         inline_hdr[16];
};
#endif //DEFINED_MLX5_HW_ETH_WQE_HEADER

struct mlx5_wqe64 {
	union {
		struct mlx5_wqe_ctrl_seg ctrl;
		uint32_t data[4];
	} ctrl;
	struct mlx5_wqe_eth_seg eseg;
	struct mlx5_wqe_data_seg dseg;
};

#endif /* WQE_H */
