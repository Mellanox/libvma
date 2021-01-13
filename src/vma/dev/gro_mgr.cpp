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
