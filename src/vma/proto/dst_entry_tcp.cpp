/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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



#include "dst_entry_tcp.h"
#include <netinet/tcp.h>

#define MODULE_NAME             "dst_tcp"

#define dst_tcp_logpanic           __log_panic
#define dst_tcp_logerr             __log_err
#define dst_tcp_logwarn            __log_warn
#define dst_tcp_loginfo            __log_info
#define dst_tcp_logdbg             __log_info_dbg
#define dst_tcp_logfunc            __log_info_fine
#define dst_tcp_logfine            __log_info_fine
#define dst_tcp_logfuncall         __log_info_finer


dst_entry_tcp::dst_entry_tcp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port,
			     socket_data &sock_data , resource_allocation_key &ring_alloc_logic):
			     dst_entry(dst_ip, dst_port, src_port, sock_data, ring_alloc_logic),
			     m_n_sysvar_tx_bufs_batch_tcp(safe_mce_sys().tx_bufs_batch_tcp)
{

}

dst_entry_tcp::~dst_entry_tcp()
{

}

transport_t dst_entry_tcp::get_transport(sockaddr_in to)
{
	NOT_IN_USE(to);
	return TRANS_VMA;
}

ssize_t dst_entry_tcp::fast_send(const iovec* p_iov, const ssize_t sz_iov, bool is_dummy, bool b_blocked /*= true*/, bool is_rexmit /*= false*/)
{
	int ret = 0;
	tx_packet_template_t* p_pkt;
	mem_buf_desc_t *p_mem_buf_desc;
	size_t total_packet_len = 0;
	// The header is aligned for fast copy but we need to maintain this diff in order to get the real header pointer easily
	size_t hdr_alignment_diff = m_header.m_aligned_l2_l3_len - m_header.m_total_hdr_len;

	tcp_iovec* p_tcp_iov = NULL;
	bool no_copy = true;
	if (likely(sz_iov == 1 && !is_rexmit)) {
		p_tcp_iov = (tcp_iovec*)p_iov;
		if (unlikely(!m_p_ring->is_active_member(p_tcp_iov->p_desc->p_desc_owner, m_id))) {
			no_copy = false;
			dst_tcp_logdbg("p_desc=%p wrong desc_owner=%p, this ring=%p. did migration occurred?", p_tcp_iov->p_desc, p_tcp_iov->p_desc->p_desc_owner, m_p_ring);
			//todo can we handle this in migration (by going over all buffers lwip hold) instead for every send?
		}
	} else {
		no_copy = false;
	}

	if (likely(no_copy)) {
		p_pkt = (tx_packet_template_t*)((uint8_t*)p_tcp_iov[0].iovec.iov_base - m_header.m_aligned_l2_l3_len);
		total_packet_len = p_tcp_iov[0].iovec.iov_len + m_header.m_total_hdr_len;
		m_header.copy_l2_ip_hdr(p_pkt);
		// We've copied to aligned address, and now we must update p_pkt to point to real
		// L2 header
		//p_pkt = (tx_packet_template_t*)((uint8_t*)p_pkt + hdr_alignment_diff);
		p_pkt->hdr.m_ip_hdr.tot_len = (htons)(p_tcp_iov[0].iovec.iov_len + m_header.m_ip_header_len);

		m_sge[0].addr = (uintptr_t)((uint8_t*)p_pkt + hdr_alignment_diff);
		m_sge[0].length = total_packet_len;

		if (total_packet_len < m_max_inline) { // inline send
			m_p_send_wqe = &m_inline_send_wqe;
		} else {
			m_p_send_wqe = &m_not_inline_send_wqe;
		}

		m_p_send_wqe->wr_id = (uintptr_t)p_tcp_iov[0].p_desc;

#ifdef DEFINED_SW_CSUM
		p_pkt->hdr.m_ip_hdr.check = 0; // use 0 at csum calculation time
		p_pkt->hdr.m_ip_hdr.check = compute_ip_checksum((unsigned short*)&p_pkt->hdr.m_ip_hdr, p_pkt->hdr.m_ip_hdr.ihl * 2);
		struct tcphdr* p_tcphdr = (struct tcphdr*)(((uint8_t*)(&(p_pkt->hdr.m_ip_hdr))+sizeof(p_pkt->hdr.m_ip_hdr)));
		p_tcphdr->check = 0;
		p_tcphdr->check = compute_tcp_checksum(&p_pkt->hdr.m_ip_hdr, (const uint16_t *)p_tcphdr);
		dst_tcp_logfine("using SW checksum calculation: p_pkt->hdr.m_ip_hdr.check=%d, p_tcphdr->check=%d", (int)p_pkt->hdr.m_ip_hdr.check, (int)p_tcphdr->check);
#endif
		send_lwip_buffer(m_id, m_p_send_wqe, b_blocked, is_dummy);

		/* for DEBUG */
		if ((uint8_t*)m_sge[0].addr < p_tcp_iov[0].p_desc->p_buffer || (uint8_t*)p_pkt < p_tcp_iov[0].p_desc->p_buffer) {
			dst_tcp_logerr("p_buffer - addr=%d, m_total_hdr_len=%zd, p_buffer=%p, type=%d, len=%d, tot_len=%d, payload=%p, hdr_alignment_diff=%zd\n",
					(int)(p_tcp_iov[0].p_desc->p_buffer - (uint8_t*)m_sge[0].addr), m_header.m_total_hdr_len,
					p_tcp_iov[0].p_desc->p_buffer, p_tcp_iov[0].p_desc->lwip_pbuf.pbuf.type,
					p_tcp_iov[0].p_desc->lwip_pbuf.pbuf.len, p_tcp_iov[0].p_desc->lwip_pbuf.pbuf.tot_len,
					p_tcp_iov[0].p_desc->lwip_pbuf.pbuf.payload, hdr_alignment_diff);
		}
	}
	else { // We don'nt support inline in this case, since we believe that this a very rare case
		p_mem_buf_desc = get_buffer(b_blocked);
		if (p_mem_buf_desc == NULL) {
			ret = -1;
			goto out;
		}

		m_header.copy_l2_ip_hdr((tx_packet_template_t*)p_mem_buf_desc->p_buffer);

		// Actually this is not the real packet len we will subtract the alignment diff at the end of the copy
		total_packet_len = m_header.m_aligned_l2_l3_len;

		for (int i = 0; i < sz_iov; ++i) {
			memcpy(p_mem_buf_desc->p_buffer + total_packet_len, p_iov[i].iov_base, p_iov[i].iov_len);
			total_packet_len += p_iov[i].iov_len;
		}

		m_sge[0].addr = (uintptr_t)(p_mem_buf_desc->p_buffer + hdr_alignment_diff);
		m_sge[0].length = total_packet_len - hdr_alignment_diff;
		// LKey will be updated in ring->send() // m_sge[0].lkey = p_mem_buf_desc->lkey; 

		p_pkt = (tx_packet_template_t*)((uint8_t*)p_mem_buf_desc->p_buffer);
		p_pkt->hdr.m_ip_hdr.tot_len = (htons)(m_sge[0].length - m_header.m_transport_header_len);
#ifdef DEFINED_SW_CSUM
		p_pkt->hdr.m_ip_hdr.check = 0; // use 0 at csum calculation time
		p_pkt->hdr.m_ip_hdr.check = compute_ip_checksum((unsigned short*)&p_pkt->hdr.m_ip_hdr, p_pkt->hdr.m_ip_hdr.ihl * 2);
		struct tcphdr* p_tcphdr = (struct tcphdr*)(((uint8_t*)(&(p_pkt->hdr.m_ip_hdr))+sizeof(p_pkt->hdr.m_ip_hdr)));
		p_tcphdr->check = 0;
		p_tcphdr->check = compute_tcp_checksum(&p_pkt->hdr.m_ip_hdr, (const uint16_t *)p_tcphdr);
		dst_tcp_logfine("using SW checksum calculation: p_pkt->hdr.m_ip_hdr.check=%d, p_tcphdr->check=%d", (int)p_pkt->hdr.m_ip_hdr.check, (int)p_tcphdr->check);
#endif
		m_p_send_wqe = &m_not_inline_send_wqe;
		m_p_send_wqe->wr_id = (uintptr_t)p_mem_buf_desc;
		vma_wr_tx_packet_attr attr = (vma_wr_tx_packet_attr)((VMA_TX_PACKET_BLOCK*b_blocked) | 
								     (VMA_TX_PACKET_DUMMY*is_dummy)  |
								      VMA_TX_PACKET_L3_CSUM          |
								      VMA_TX_PACKET_L4_CSUM);
		send_ring_buffer(m_id, m_p_send_wqe, attr);

		/* for DEBUG */
		if ((uint8_t*)m_sge[0].addr < p_mem_buf_desc->p_buffer) {
			dst_tcp_logerr("p_buffer - addr=%d, m_total_hdr_len=%zd, p_buffer=%p, type=%d, len=%d, tot_len=%d, payload=%p, hdr_alignment_diff=%zd\n",
					(int)(p_mem_buf_desc->p_buffer - (uint8_t*)m_sge[0].addr), m_header.m_total_hdr_len,
					p_mem_buf_desc->p_buffer, p_mem_buf_desc->lwip_pbuf.pbuf.type,
					p_mem_buf_desc->lwip_pbuf.pbuf.len, p_mem_buf_desc->lwip_pbuf.pbuf.tot_len,
					p_mem_buf_desc->lwip_pbuf.pbuf.payload, hdr_alignment_diff);
		}
	}

	if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
		m_p_tx_mem_buf_desc_list = m_p_ring->mem_buf_tx_get(m_id, b_blocked, m_n_sysvar_tx_bufs_batch_tcp);
	}

out:
	if (unlikely(is_rexmit)) {
		m_p_ring->inc_tx_retransmissions(m_id);
	}

	return ret;
}



ssize_t dst_entry_tcp::slow_send(const iovec* p_iov, size_t sz_iov, bool is_dummy, struct vma_rate_limit_t &rate_limit, bool b_blocked /*= true*/, bool is_rexmit /*= false*/, int flags /*= 0*/, socket_fd_api* sock /*= 0*/, tx_call_t call_type /*= 0*/)
{
	ssize_t ret_val = -1;

	NOT_IN_USE(sock);
	NOT_IN_USE(call_type);
	NOT_IN_USE(flags);

	m_slow_path_lock.lock();

	prepare_to_send(rate_limit, true);

	if (m_b_is_offloaded) {
		if (!is_valid()) { // That means that the neigh is not resolved yet
			//there is a copy inside so we should not update any ref-counts
			ret_val = pass_buff_to_neigh(p_iov, sz_iov);
		}
		else {
			ret_val = fast_send(p_iov, sz_iov, is_dummy, b_blocked, is_rexmit);
		}
	}
	else {
		dst_tcp_logdbg("Dst_entry is not offloaded, bug?");
	}
	m_slow_path_lock.unlock();
	return ret_val;
}

ssize_t dst_entry_tcp::slow_send_neigh( const iovec* p_iov, size_t sz_iov, struct vma_rate_limit_t &rate_limit)
{
	ssize_t ret_val = -1;

	m_slow_path_lock.lock();

	prepare_to_send(rate_limit, true);

	if (m_b_is_offloaded) {
		ret_val = pass_buff_to_neigh(p_iov, sz_iov);
	}
	else {
		dst_tcp_logdbg("Dst_entry is not offloaded, bug?");
	}

	m_slow_path_lock.unlock();
	return ret_val;
}

//The following function supposed to be called under m_lock
void dst_entry_tcp::configure_headers()
{
	m_header.init();
	dst_entry::configure_headers();
}

ssize_t dst_entry_tcp::pass_buff_to_neigh(const iovec * p_iov, size_t & sz_iov, uint16_t packet_id)
{
	NOT_IN_USE(packet_id);
	m_header_neigh.init();
	m_header_neigh.configure_tcp_ports(m_dst_port, m_src_port);
	return(dst_entry::pass_buff_to_neigh(p_iov, sz_iov));
}

mem_buf_desc_t* dst_entry_tcp::get_buffer(bool b_blocked /*=false*/)
{
	set_tx_buff_list_pending(false);

	// Get a bunch of tx buf descriptor and data buffers
	if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
		m_p_tx_mem_buf_desc_list = m_p_ring->mem_buf_tx_get(m_id, b_blocked, m_n_sysvar_tx_bufs_batch_tcp);
	}

	mem_buf_desc_t* p_mem_buf_desc = m_p_tx_mem_buf_desc_list;
	if (unlikely(p_mem_buf_desc == NULL)) {
		dst_tcp_logfunc("silent packet drop, no buffers!");
	}
	else {
		m_p_tx_mem_buf_desc_list = m_p_tx_mem_buf_desc_list->p_next_desc;
		p_mem_buf_desc->p_next_desc = NULL;
		// for TX, set lwip payload to the data segment.
		// lwip will send it with payload pointing to the tcp header.
		p_mem_buf_desc->lwip_pbuf.pbuf.payload = (u8_t *)p_mem_buf_desc->p_buffer + m_header.m_aligned_l2_l3_len + sizeof(struct tcphdr);
	}

	return p_mem_buf_desc;
}

//called from lwip under sockinfo_tcp lock
//handle un-chained pbuf
// only single p_desc
void dst_entry_tcp::put_buffer(mem_buf_desc_t * p_desc)
{
	//todo accumulate buffers?

	if (unlikely(p_desc == NULL))
		return;

	if (likely(m_p_ring->is_member(p_desc->p_desc_owner))) {
		p_desc->p_desc_owner->mem_buf_desc_return_to_owner_tx(p_desc);
	} else {

		//potential race, ref is protected here by tcp lock, and in ring by ring_tx lock
		if (likely(p_desc->lwip_pbuf.pbuf.ref))
			p_desc->lwip_pbuf.pbuf.ref--;
		else
			dst_tcp_logerr("ref count of %p is already zero, double free??", p_desc);

		if (p_desc->lwip_pbuf.pbuf.ref == 0) {
			p_desc->p_next_desc = NULL;
			g_buffer_pool_tx->put_buffers_thread_safe(p_desc);
		}
	}
}
