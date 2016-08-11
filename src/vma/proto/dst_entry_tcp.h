/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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
	ssize_t slow_send_neigh(const iovec* p_iov, size_t sz_iov);

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

private:
	const uint32_t       m_n_sysvar_tx_bufs_batch_tcp;
};

#endif /* DST_ENTRY_TCP_H */
