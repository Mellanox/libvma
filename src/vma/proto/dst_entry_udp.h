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


#ifndef DST_ENTRY_UDP_H
#define DST_ENTRY_UDP_H

#include "vma/proto/dst_entry.h"

class dst_entry_udp : public dst_entry
{
public:
	dst_entry_udp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, int owner_fd);
	virtual ~dst_entry_udp();

	virtual ssize_t 	slow_send(const iovec* p_iov, size_t sz_iov, bool b_blocked = true, bool is_rexmit = false, int flags = 0, socket_fd_api* sock = 0, tx_call_t call_type = TX_UNDEF);
	virtual ssize_t 	fast_send(const struct iovec* p_iov, const ssize_t sz_iov, bool b_blocked = true, bool is_rexmit = false, bool dont_inline = false);

protected:
	virtual transport_t 	get_transport(sockaddr_in to);
	virtual uint8_t 	get_protocol_type() const { return IPPROTO_UDP; };
	virtual uint32_t 	get_inline_sge_num() { return 2; };
	virtual ibv_sge*	get_sge_lst_4_inline_send() { return m_sge; };
	virtual ibv_sge*	get_sge_lst_4_not_inline_send() { return &m_sge[1]; };
	virtual void 		configure_headers();
	virtual void 		init_sge();
	virtual ssize_t 	pass_buff_to_neigh(const iovec *p_iov, size_t & sz_iov, uint16_t packet_id = 0);
	atomic_t m_a_tx_ip_id;
	size_t m_n_tx_ip_id;
};

#endif /* DST_ENTRY_UDP_H */
