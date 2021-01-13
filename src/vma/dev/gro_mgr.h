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
