/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef DST_ENTRY_UDP_H
#define DST_ENTRY_UDP_H

#include "vma/proto/dst_entry.h"

class dst_entry_udp : public dst_entry
{
public:
	dst_entry_udp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port,
			socket_data &sock_data, resource_allocation_key &ring_alloc_logic);
	virtual ~dst_entry_udp();

#ifdef DEFINED_TSO
        ssize_t fast_send(const iovec* p_iov, const ssize_t sz_iov, vma_send_attr attr);
	ssize_t slow_send(const iovec* p_iov, const ssize_t sz_iov, vma_send_attr attr,
			struct vma_rate_limit_t &rate_limit, int flags = 0,
			socket_fd_api* sock = 0, tx_call_t call_type = TX_UNDEF);
#else
	virtual ssize_t 	slow_send(const iovec* p_iov, size_t sz_iov, bool is_dummy, struct vma_rate_limit_t &rate_limit, bool b_blocked = true, bool is_rexmit = false, int flags = 0, socket_fd_api* sock = 0, tx_call_t call_type = TX_UNDEF);
	virtual ssize_t 	fast_send(const iovec* p_iov, const ssize_t sz_iov, bool is_dummy, bool b_blocked = true, bool is_rexmit = false);
#endif /* DEFINED_TSO */

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

	const uint32_t m_n_sysvar_tx_bufs_batch_udp;
	const bool m_b_sysvar_tx_nonblocked_eagains;
	const thread_mode_t	m_sysvar_thread_mode;
	const uint32_t m_n_sysvar_tx_prefetch_bytes;
};

#endif /* DST_ENTRY_UDP_H */
