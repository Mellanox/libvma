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



#include "dst_entry_tcp.h"
#include <netinet/tcp.h>

#define MODULE_NAME             "dst_tcp"

#define dst_tcp_logpanic           __log_panic
#define dst_tcp_logerr             __log_err
#define dst_tcp_logwarn            __log_warn
#define dst_tcp_loginfo            __log_info
#define dst_tcp_logdbg             __log_info_dbg
#define dst_tcp_logfunc            __log_info_func
#define dst_tcp_logfuncall         __log_info_funcall


dst_entry_tcp::dst_entry_tcp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, int owner_fd):
			       dst_entry(dst_ip, dst_port, src_port, owner_fd)
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

ssize_t dst_entry_tcp::fast_send(const struct iovec* p_iov, const ssize_t sz_iov, bool b_blocked /*= true*/, bool is_rexmit /*= false*/, bool dont_inline /*= false*/)
{
	NOT_IN_USE(is_rexmit);

	tx_packet_template_t* p_pkt;
	mem_buf_desc_t *p_mem_buf_desc;
	size_t total_packet_len = 0;
	// The header is aligned for fast copy but we need to maintain this diff in order to get the real header pointer easily
	size_t hdr_alignment_diff = m_header.m_aligned_l2_l3_len - m_header.m_total_hdr_len;

	tcp_iovec* p_tcp_iov = NULL;
	bool no_copy = true;
	if (likely(sz_iov == 1 && !is_rexmit)) {
		p_tcp_iov = (tcp_iovec*)p_iov;
		if (unlikely(p_tcp_iov->p_desc->p_desc_owner != m_p_ring)) {
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

		if (!dont_inline && (total_packet_len < m_max_inline)) { // inline send
			m_p_send_wqe = &m_inline_send_wqe;

		} else {
			m_p_send_wqe = &m_not_inline_send_wqe;
		}

                m_p_send_wqe->wr_id = (uintptr_t)p_tcp_iov[0].p_desc;

                m_p_ring->send_lwip_buffer(m_p_send_wqe, b_blocked);
	}
	else { // We don'nt support inline in this case, since we believe that this a very rare case
		p_mem_buf_desc = get_buffer(b_blocked);
		if (p_mem_buf_desc == NULL) {
			return -1;
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
		m_p_send_wqe = &m_not_inline_send_wqe;
                m_p_send_wqe->wr_id = (uintptr_t)p_mem_buf_desc;
                m_p_ring->send_ring_buffer(m_p_send_wqe, b_blocked);
	}

#ifndef __COVERITY__
        struct tcphdr* p_tcp_h = (struct tcphdr*)(((uint8_t*)(&(p_pkt->hdr.m_ip_hdr))+sizeof(p_pkt->hdr.m_ip_hdr)));
        dst_tcp_logfunc("Tx TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
                        ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest),
                        p_tcp_h->urg?"U":"", p_tcp_h->ack?"A":"", p_tcp_h->psh?"P":"",
                        p_tcp_h->rst?"R":"", p_tcp_h->syn?"S":"", p_tcp_h->fin?"F":"",
                        ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window),
                        total_packet_len- p_tcp_h->doff*4 -34);
#endif


	return 0;
}



ssize_t dst_entry_tcp::slow_send(const iovec* p_iov, size_t sz_iov, bool b_blocked /*= true*/, bool is_rexmit /*= false*/, int flags /*= 0*/, socket_fd_api* sock /*= 0*/, tx_call_t call_type /*= 0*/)
{
	ssize_t ret_val = -1;

	NOT_IN_USE(sock);
	NOT_IN_USE(call_type);
	NOT_IN_USE(flags);

	m_slow_path_lock.lock();

	prepare_to_send(true);

	if (m_b_is_offloaded) {
		if (!is_valid()) { // That means that the neigh is not resolved yet
			//there is a copy inside so we should not update any ref-counts
			ret_val = pass_buff_to_neigh(p_iov, sz_iov);
		}
		else {
			ret_val = fast_send(p_iov, sz_iov, b_blocked, is_rexmit);
		}
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

bool dst_entry_tcp::conf_hdrs_and_snd_wqe()
{
	bool ret_val = dst_entry::conf_hdrs_and_snd_wqe();
	m_p_send_wqe_handler->enable_hw_csum(m_not_inline_send_wqe);

	return ret_val;
}

ssize_t dst_entry_tcp::pass_buff_to_neigh(const iovec * p_iov, size_t & sz_iov, uint16_t packet_id)
{
	NOT_IN_USE(packet_id);
	m_header.init();
	return(dst_entry::pass_buff_to_neigh(p_iov, sz_iov));
}

mem_buf_desc_t* dst_entry_tcp::get_buffer(bool b_blocked /*=false*/)
{
	// Get a bunch of tx buf descriptor and data buffers
	if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
		m_p_tx_mem_buf_desc_list = m_p_ring->mem_buf_tx_get(b_blocked, 16);
	}

	mem_buf_desc_t* p_mem_buf_desc = m_p_tx_mem_buf_desc_list;
	if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
		dst_tcp_logfunc("silent packet drop, no buffers!");
	}
	else {
		m_p_tx_mem_buf_desc_list = m_p_tx_mem_buf_desc_list->p_next_desc;
		p_mem_buf_desc->p_next_desc = NULL;
		p_mem_buf_desc->lwip_pbuf.pbuf.payload = (u8_t *)p_mem_buf_desc->p_buffer + m_header.m_total_hdr_len;
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

	if (likely(p_desc->p_desc_owner == m_p_ring)) {
		m_p_ring->mem_buf_desc_return_single_to_owner_tx(p_desc);
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
