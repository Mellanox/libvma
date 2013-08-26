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
