/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef DST_ENTRY_UDP_H
#define DST_ENTRY_UDP_H

#include "vma/proto/dst_entry.h"

class dst_entry_udp : public dst_entry
{
public:
	dst_entry_udp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port,
			socket_data &sock_data, resource_allocation_key &ring_alloc_logic);
	virtual ~dst_entry_udp();

	virtual ssize_t 	slow_send(const iovec* p_iov, size_t sz_iov, bool is_dummy, struct vma_rate_limit_t &rate_limit, bool b_blocked = true, bool is_rexmit = false, int flags = 0, socket_fd_api* sock = 0, tx_call_t call_type = TX_UNDEF);
	virtual ssize_t 	fast_send(const iovec* p_iov, const ssize_t sz_iov, bool is_dummy, bool b_blocked = true, bool is_rexmit = false);

protected:
	virtual transport_t 	get_transport(sockaddr_in to);
	virtual uint8_t 	get_protocol_type() const { return IPPROTO_UDP; };
	virtual uint32_t 	get_inline_sge_num() { return 2; };
	virtual ibv_sge*	get_sge_lst_4_inline_send() { return m_sge; };
	virtual ibv_sge*	get_sge_lst_4_not_inline_send() { return &m_sge[1]; };
	virtual void 		configure_headers();
	virtual void 		init_sge();
	virtual ssize_t 	pass_buff_to_neigh(const iovec *p_iov, size_t sz_iov, uint16_t packet_id = 0);
	atomic_t m_a_tx_ip_id;
	size_t m_n_tx_ip_id;

private:

	inline ssize_t fast_send_not_fragmented(const iovec* p_iov, const ssize_t sz_iov, vma_wr_tx_packet_attr attr, size_t sz_udp_payload, ssize_t sz_data_payload);
	ssize_t fast_send_fragmented(const iovec* p_iov, const ssize_t sz_iov, vma_wr_tx_packet_attr attr, size_t sz_udp_payload, ssize_t sz_data_payload);
	ssize_t check_payload_size(const iovec* p_iov, ssize_t sz_iov);

	const uint32_t m_n_sysvar_tx_bufs_batch_udp;
	const bool m_b_sysvar_tx_nonblocked_eagains;
	const thread_mode_t	m_sysvar_thread_mode;
	const uint32_t m_n_sysvar_tx_prefetch_bytes;
};

#endif /* DST_ENTRY_UDP_H */
