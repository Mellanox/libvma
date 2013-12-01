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


#ifndef DST_ENTRY_TCP_H
#define DST_ENTRY_TCP_H

#include "vma/proto/dst_entry.h"

/* Structure for TCP scatter/gather I/O.  */
typedef struct tcp_iovec
{
	struct iovec iovec;
	mem_buf_desc_t* p_desc;
}tcp_iovec;

class dst_entry_tcp : public dst_entry
{
public:
	dst_entry_tcp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, int owner_fd);
	virtual ~dst_entry_tcp();

	virtual ssize_t fast_send(const struct iovec* p_iov, const ssize_t sz_iov, bool b_blocked = true, bool is_rexmit = false, bool dont_inline = false);
	ssize_t slow_send(const iovec* p_iov, size_t sz_iov, bool b_blocked = true, bool is_rexmit = false, int flags = 0, socket_fd_api* sock = 0, tx_call_t call_type = TX_UNDEF);

	mem_buf_desc_t* get_buffer(bool b_blocked = false);
	void put_buffer(mem_buf_desc_t * p_desc);

protected:
	transport_t 		get_transport(sockaddr_in to);
	virtual uint8_t 	get_protocol_type() const { return IPPROTO_TCP; };
	virtual uint32_t 	get_inline_sge_num() { return 1; };
	virtual ibv_sge*	get_sge_lst_4_inline_send() { return m_sge; };
	virtual ibv_sge*	get_sge_lst_4_not_inline_send() { return m_sge; };

	virtual void		configure_headers();
	virtual bool		conf_hdrs_and_snd_wqe();
	virtual ssize_t 	pass_buff_to_neigh(const iovec *p_iov, size_t & sz_iov, uint16_t packet_id = 0);
};

#endif /* DST_ENTRY_TCP_H */
