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
	rfs_uc_tcp_gro(flow_tuple *flow_spec_5t, ring *p_ring,  rfs_rule_filter* rule_filter = NULL);

	virtual bool rx_dispatch_packet(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array);

	void flush(void* pv_fd_ready_array);

private:

	inline void flush_gro_desc(void* pv_fd_ready_array);
	inline void add_packet(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h);
	inline void init_gro_desc(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h);
	inline bool tcp_ip_check(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h);
	inline bool timestamp_check(tcphdr* p_tcp_h);

	pkt_rcvr_sink* m_p_orig_sink;
	gro_mgr* m_p_gro_mgr;
	bool m_b_active;
	bool m_b_reserved;
	struct  gro_mem_buf_desc m_gro_desc;
	uint32_t m_n_buf_max;
	uint32_t m_n_byte_max;
};


#endif /* RFS_UC_TCP_GRO_H */
