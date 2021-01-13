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


#ifndef RFS_UC_TCP_GRO_H
#define RFS_UC_TCP_GRO_H

#include "vma/dev/rfs_uc.h"
#include <netinet/tcp.h>
/**
 * @class rfs_uc_tcp_gro
 *
 * Object to manages the sink list of a UC TCP GRO flow
 * This object is used for maintaining the sink list and dispatching packets
 *
 */

struct gro_mem_buf_desc {
	mem_buf_desc_t* p_first;
	mem_buf_desc_t* p_last;
	iphdr* p_ip_h;
	tcphdr* p_tcp_h;
	uint32_t buf_count;
	uint32_t next_seq;
	uint32_t ack;
	uint32_t ts_present;
	uint32_t tsval;
	uint32_t tsecr;
	uint16_t ip_tot_len;
	uint16_t wnd;
} typedef gro_mem_buf_desc_t;

class gro_mgr;

class rfs_uc_tcp_gro : public rfs_uc
{
public:
	rfs_uc_tcp_gro(flow_tuple *flow_spec_5t, ring_slave *p_ring,
		       rfs_rule_filter* rule_filter = NULL, uint32_t flow_tag_id = 0);

	virtual bool rx_dispatch_packet(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array);

	void flush(void* pv_fd_ready_array);

private:

	inline void flush_gro_desc(void* pv_fd_ready_array);
	inline void add_packet(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h);
	inline void init_gro_desc(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h);
	inline bool tcp_ip_check(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h);
	inline bool timestamp_check(tcphdr* p_tcp_h);

	gro_mgr* m_p_gro_mgr;
	bool m_b_active;
	bool m_b_reserved;
	struct  gro_mem_buf_desc m_gro_desc;
	uint32_t m_n_buf_max;
	uint32_t m_n_byte_max;
};


#endif /* RFS_UC_TCP_GRO_H */
