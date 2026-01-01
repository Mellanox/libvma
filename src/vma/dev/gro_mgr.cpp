/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "vma/dev/gro_mgr.h"
#include "vma/dev/rfs_uc_tcp_gro.h"

#define MODULE_NAME "gro_mgr"

gro_mgr::gro_mgr(uint32_t flow_max, uint32_t buf_max) : m_n_flow_max(flow_max), m_n_buf_max(buf_max), m_n_flow_count(0)
{
	m_p_rfs_arr = new rfs_uc_tcp_gro*[flow_max];
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_rfs_arr) {
		__log_panic("could not allocate memory");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

gro_mgr::~gro_mgr()
{
	delete [] m_p_rfs_arr;
}

bool gro_mgr::reserve_stream(rfs_uc_tcp_gro* rfs_uc_tcp_gro)
{
	if (is_stream_max()) return false;

	m_p_rfs_arr[m_n_flow_count] = rfs_uc_tcp_gro;
	m_n_flow_count++;
	return true;
}

bool gro_mgr::is_stream_max()
{
	return (m_n_flow_count >= m_n_flow_max);
}



void gro_mgr::flush_all(void* pv_fd_ready_array)
{
	for (uint32_t i = 0; i < m_n_flow_count; i++) {
		m_p_rfs_arr[i]->flush(pv_fd_ready_array);
	}
	m_n_flow_count = 0;
}
