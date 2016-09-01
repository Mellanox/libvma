/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
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
