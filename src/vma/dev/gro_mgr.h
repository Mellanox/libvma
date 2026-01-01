/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef GRO_MGR_H_
#define GRO_MGR_H_

#include <stdint.h>

#define MAX_AGGR_BYTE_PER_STREAM 0xFFFF
#define MAX_GRO_BUFS 32

class rfs_uc_tcp_gro;

class gro_mgr
{
public:
	gro_mgr(uint32_t flow_max, uint32_t buf_max);
	bool 		reserve_stream(rfs_uc_tcp_gro* rfs_uc_tcp_gro);
	bool 		is_stream_max();
	inline uint32_t get_buf_max() { return m_n_buf_max;}
	inline uint32_t get_byte_max() { return MAX_AGGR_BYTE_PER_STREAM;}
	void 		flush_all(void* pv_fd_ready_array);
	virtual 	~gro_mgr();

private:
	const uint32_t 	m_n_flow_max;
	const uint32_t 	m_n_buf_max;

	uint32_t 	m_n_flow_count;

	rfs_uc_tcp_gro** m_p_rfs_arr;
};

#endif /* GRO_MGR_H_ */
