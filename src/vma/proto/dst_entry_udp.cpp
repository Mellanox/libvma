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


#include "utils/bullseye.h"
#include "vma/util/utils.h"
#include "dst_entry_udp.h"

#define MODULE_NAME             "dst_udp"

#define dst_udp_logpanic           __log_panic
#define dst_udp_logerr             __log_err
#define dst_udp_logwarn            __log_warn
#define dst_udp_loginfo            __log_info
#define dst_udp_logdbg             __log_info_dbg
#define dst_udp_logfunc            __log_info_func
#define dst_udp_logfuncall         __log_info_funcall


dst_entry_udp::dst_entry_udp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port,
			     socket_data &sock_data, resource_allocation_key &ring_alloc_logic):
	dst_entry(dst_ip, dst_port, src_port, sock_data, ring_alloc_logic),
	m_n_sysvar_tx_bufs_batch_udp(safe_mce_sys().tx_bufs_batch_udp),
	m_b_sysvar_tx_nonblocked_eagains(safe_mce_sys().tx_nonblocked_eagains),
	m_sysvar_thread_mode(safe_mce_sys().thread_mode),
	m_n_sysvar_tx_prefetch_bytes(safe_mce_sys().tx_prefetch_bytes)
{
	dst_udp_logdbg("%s", to_str().c_str());
	atomic_set(&m_a_tx_ip_id, 0);
	m_n_tx_ip_id = 0;
}

dst_entry_udp::~dst_entry_udp()
{
	dst_udp_logdbg("%s", to_str().c_str());
}

transport_t dst_entry_udp::get_transport(sockaddr_in to)
{
	return  __vma_match_udp_sender(TRANS_VMA, safe_mce_sys().app_id, (sockaddr *)(&to), sizeof to);
}

//The following function supposed to be called under m_lock
void dst_entry_udp::configure_headers()
{
	m_header.init();
	m_header.configure_udp_header(m_dst_port, m_src_port);
	dst_entry::configure_headers();
}

inline ssize_t dst_entry_udp::fast_send_not_fragmented(const iovec* p_iov, const ssize_t sz_iov, vma_wr_tx_packet_attr attr,  size_t sz_udp_payload, ssize_t sz_data_payload)
{
	mem_buf_desc_t* p_mem_buf_desc;
	bool b_blocked = is_set(attr, VMA_TX_PACKET_BLOCK);
	// Get a bunch of tx buf descriptor and data buffers
	if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
		m_p_tx_mem_buf_desc_list = m_p_ring->mem_buf_tx_get(m_id, b_blocked, m_n_sysvar_tx_bufs_batch_udp);

		if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
			if (b_blocked) {
				dst_udp_logdbg("Error when blocking for next tx buffer (errno=%d %m)", errno);
			}
			else {
				dst_udp_logfunc("Packet dropped. NonBlocked call but not enough tx buffers. Returning OK");
				if (!m_b_sysvar_tx_nonblocked_eagains) return sz_data_payload;
			}
			errno = EAGAIN;
			return -1;
		}
	}
	// Disconnect the first buffer from the list
	p_mem_buf_desc = m_p_tx_mem_buf_desc_list;
	m_p_tx_mem_buf_desc_list = m_p_tx_mem_buf_desc_list->p_next_desc;
	p_mem_buf_desc->p_next_desc = NULL;

	set_tx_buff_list_pending(false);

	// Check if inline is possible
	if (sz_iov == 1 && (sz_data_payload + m_header.m_total_hdr_len) < m_max_inline) {
		m_p_send_wqe = &m_inline_send_wqe;

		m_header.m_header.hdr.m_udp_hdr.len = htons((uint16_t)sz_udp_payload);
		m_header.m_header.hdr.m_ip_hdr.tot_len = htons(m_header.m_ip_header_len + sz_udp_payload);

#ifdef DEFINED_SW_CSUM
		dst_udp_logfunc("using SW checksum calculation");
		m_header.m_header.hdr.m_ip_hdr.check = 0; // use 0 at csum calculation time
		m_header.m_header.hdr.m_ip_hdr.check = compute_ip_checksum((unsigned short*)&m_header.m_header.hdr.m_ip_hdr, m_header.m_header.hdr.m_ip_hdr.ihl * 2);
		m_header.m_header.hdr.m_udp_hdr.check = 0;
#endif

		//m_sge[0].addr  already points to the header
		//so we just need to update the payload addr + len
		m_sge[1].length = p_iov[0].iov_len;
		m_sge[1].addr = (uintptr_t)p_iov[0].iov_base;
	} else {
		m_p_send_wqe = &m_not_inline_send_wqe;

		tx_packet_template_t *p_pkt = (tx_packet_template_t*)p_mem_buf_desc->p_buffer;
		size_t hdr_len = m_header.m_transport_header_len + m_header.m_ip_header_len + sizeof(udphdr); // Add count of L2 (ipoib or mac) header length and udp header

		if (m_n_sysvar_tx_prefetch_bytes) {
			prefetch_range(p_mem_buf_desc->p_buffer + m_header.m_transport_header_tx_offset,
					min(sz_udp_payload, (size_t)m_n_sysvar_tx_prefetch_bytes));
		}

		m_header.copy_l2_ip_udp_hdr(p_pkt);
		p_pkt->hdr.m_udp_hdr.len = htons((uint16_t)sz_udp_payload);
		p_pkt->hdr.m_ip_hdr.frag_off = htons(0);

		// Update ip header specific values
		p_pkt->hdr.m_ip_hdr.id = 0;
		p_pkt->hdr.m_ip_hdr.tot_len = htons(m_header.m_ip_header_len + sz_udp_payload);

#ifdef DEFINED_SW_CSUM
		dst_udp_logfunc("using SW checksum calculation");
		p_pkt->hdr.m_ip_hdr.check = 0; // use 0 at csum calculation time
		p_pkt->hdr.m_ip_hdr.check = compute_ip_checksum((unsigned short*)&p_pkt->hdr.m_ip_hdr, p_pkt->hdr.m_ip_hdr.ihl * 2);
		p_pkt->hdr.m_udp_hdr.check = 0;
#endif

		// Update the payload addr + len
		m_sge[1].length = sz_data_payload + hdr_len;
		m_sge[1].addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)m_header.m_transport_header_tx_offset);

		// Calc payload start point (after the udp header if present else just after ip header)
		uint8_t* p_payload = p_mem_buf_desc->p_buffer + m_header.m_transport_header_tx_offset + hdr_len;

		// Copy user data to our tx buffers
		int ret = memcpy_fromiovec(p_payload, p_iov, sz_iov, 0, sz_data_payload);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret != (int)sz_data_payload) {
			dst_udp_logerr("memcpy_fromiovec error (sz_user_data_to_copy=%d, ret=%d)", sz_data_payload, ret);
			m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
			errno = EINVAL;
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

#ifndef DEFINED_SW_CSUM
	attr = (vma_wr_tx_packet_attr)(attr|VMA_TX_PACKET_L3_CSUM|VMA_TX_PACKET_L4_CSUM);
#endif

	m_p_send_wqe->wr_id = (uintptr_t)p_mem_buf_desc;
	send_ring_buffer(m_id, m_p_send_wqe, attr);

	// request tx buffers for the next packets
	if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
		m_p_tx_mem_buf_desc_list = m_p_ring->mem_buf_tx_get(m_id, b_blocked, m_n_sysvar_tx_bufs_batch_udp);
	}

	// If all went well :) then return the user data count transmitted
	return sz_data_payload;
}

ssize_t dst_entry_udp::fast_send_fragmented(const iovec* p_iov, const ssize_t sz_iov, vma_wr_tx_packet_attr attr, size_t sz_udp_payload, ssize_t sz_data_payload)
{
	tx_packet_template_t *p_pkt;
	mem_buf_desc_t* p_mem_buf_desc = NULL, *tmp;

	m_p_send_wqe = &m_fragmented_send_wqe;

	// Find number of ip fragments (-> packets, buffers, buffer descs...)
	int n_num_frags = (sz_udp_payload + m_max_ip_payload_size - 1) / m_max_ip_payload_size;
	uint16_t packet_id = (m_sysvar_thread_mode > THREAD_MODE_SINGLE) ?
			atomic_fetch_and_inc(&m_a_tx_ip_id) :
			m_n_tx_ip_id++;
	packet_id = htons(packet_id);

	bool b_blocked = is_set(attr, VMA_TX_PACKET_BLOCK);

	dst_udp_logfunc("udp info: payload_sz=%d, frags=%d, scr_port=%d, dst_port=%d, blocked=%s, ", sz_data_payload, n_num_frags, ntohs(m_header.m_header.hdr.m_udp_hdr.source), ntohs(m_dst_port), b_blocked?"true":"false");

	// Get all needed tx buf descriptor and data buffers
	p_mem_buf_desc = m_p_ring->mem_buf_tx_get(m_id, b_blocked, n_num_frags);

	if (unlikely(p_mem_buf_desc == NULL)) {
		if (b_blocked) {
			dst_udp_logdbg("Error when blocking for next tx buffer (errno=%d %m)", errno);
		}
		else {
			dst_udp_logfunc("Packet dropped. NonBlocked call but not enough tx buffers. Returning OK");
			if (!m_b_sysvar_tx_nonblocked_eagains) return sz_data_payload;
		}
		errno = EAGAIN;
		return -1;
	}

	// Int for counting offset inside the ip datagram payload
	uint32_t n_ip_frag_offset = 0;
	size_t sz_user_data_offset = 0;

	while (n_num_frags--) {
		// Calc this ip datagram fragment size (include any udp header)
		size_t sz_ip_frag = min((size_t)m_max_ip_payload_size, (sz_udp_payload - n_ip_frag_offset));
		size_t sz_user_data_to_copy = sz_ip_frag;
		size_t hdr_len = m_header.m_transport_header_len + m_header.m_ip_header_len; // Add count of L2 (ipoib or mac) header length

		if (m_n_sysvar_tx_prefetch_bytes) {
			prefetch_range(p_mem_buf_desc->p_buffer + m_header.m_transport_header_tx_offset,
					min(sz_ip_frag, (size_t)m_n_sysvar_tx_prefetch_bytes));
		}

		p_pkt = (tx_packet_template_t*)p_mem_buf_desc->p_buffer;

		uint16_t frag_off = 0;
		if (n_num_frags) {
			frag_off |= MORE_FRAGMENTS_FLAG;
		}

		if (n_ip_frag_offset == 0) {
			m_header.copy_l2_ip_udp_hdr(p_pkt);
			// Add count of udp header length
			hdr_len += sizeof(udphdr);

			// Copy less from user data
			sz_user_data_to_copy -= sizeof(udphdr);

			// Only for first fragment add the udp header
			p_pkt->hdr.m_udp_hdr.len = htons((uint16_t)sz_udp_payload);
		}
		else {
			m_header.copy_l2_ip_hdr(p_pkt);
			frag_off |= FRAGMENT_OFFSET & (n_ip_frag_offset / 8);
		}

		p_pkt->hdr.m_ip_hdr.frag_off = htons(frag_off);
		// Update ip header specific values
		p_pkt->hdr.m_ip_hdr.id = packet_id;
		p_pkt->hdr.m_ip_hdr.tot_len = htons(m_header.m_ip_header_len + sz_ip_frag);

		// Calc payload start point (after the udp header if present else just after ip header)
		uint8_t* p_payload = p_mem_buf_desc->p_buffer + m_header.m_transport_header_tx_offset + hdr_len;

		// Copy user data to our tx buffers
		int ret = memcpy_fromiovec(p_payload, p_iov, sz_iov, sz_user_data_offset, sz_user_data_to_copy);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret != (int)sz_user_data_to_copy) {
			dst_udp_logerr("memcpy_fromiovec error (sz_user_data_to_copy=%d, ret=%d)", sz_user_data_to_copy, ret);
			m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
			errno = EINVAL;
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		dst_udp_logfunc("ip fragmentation detected, using SW checksum calculation");
		p_pkt->hdr.m_ip_hdr.check = 0; // use 0 at csum calculation time
		p_pkt->hdr.m_ip_hdr.check = compute_ip_checksum((unsigned short*)&p_pkt->hdr.m_ip_hdr, p_pkt->hdr.m_ip_hdr.ihl * 2);

		m_sge[1].addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)m_header.m_transport_header_tx_offset);
		m_sge[1].length = sz_user_data_to_copy + hdr_len;
		m_p_send_wqe->wr_id = (uintptr_t)p_mem_buf_desc;

		dst_udp_logfunc("%s packet_sz=%d, payload_sz=%d, ip_offset=%d id=%d", m_header.to_str().c_str(),
				m_sge[1].length - m_header.m_transport_header_len, sz_user_data_to_copy,
				n_ip_frag_offset, ntohs(packet_id));

		tmp = p_mem_buf_desc->p_next_desc;
		p_mem_buf_desc->p_next_desc = NULL;

		// We don't check the return valuse of post send when we reach the HW we consider that we completed our job
		send_ring_buffer(m_id, m_p_send_wqe, attr);

		p_mem_buf_desc = tmp;

		// Update ip frag offset position
		n_ip_frag_offset += sz_ip_frag;

		// Update user data start offset copy location
		sz_user_data_offset += sz_user_data_to_copy;

	} // while(n_num_frags)

	// If all went well :) then return the user data count transmitted
	return sz_data_payload;
}

ssize_t dst_entry_udp::fast_send(const iovec* p_iov, const ssize_t sz_iov,
				bool is_dummy, bool b_blocked /*=true*/, bool is_rexmit /*=false*/)
{
	NOT_IN_USE(is_rexmit);

	// Calc user data payload size
	ssize_t sz_data_payload = 0;
	for (ssize_t i = 0; i < sz_iov; i++)
		sz_data_payload += p_iov[i].iov_len;

	if (unlikely(sz_data_payload > 65536)) {
		dst_udp_logfunc("sz_data_payload=%d, to_port=%d, local_port=%d, b_blocked=%s", sz_data_payload, ntohs(m_dst_port), ntohs(m_src_port), b_blocked?"true":"false");
		dst_udp_logfunc("sz_data_payload=%d exceeds max of 64KB", sz_data_payload);
		errno = EMSGSIZE;
		return -1;
	}

	// Calc udp payload size
	size_t sz_udp_payload = sz_data_payload + sizeof(struct udphdr);
	vma_wr_tx_packet_attr attr = (vma_wr_tx_packet_attr)((VMA_TX_PACKET_BLOCK * b_blocked) | (VMA_TX_PACKET_DUMMY * is_dummy));
	if (sz_udp_payload <= (size_t)m_max_udp_payload_size) {
		return fast_send_not_fragmented(p_iov, sz_iov, attr, sz_udp_payload, sz_data_payload);
	} else {
		return fast_send_fragmented(p_iov, sz_iov, attr, sz_udp_payload, sz_data_payload);
	}
}

ssize_t dst_entry_udp::slow_send(const iovec* p_iov, size_t sz_iov, bool is_dummy,
				 struct vma_rate_limit_t &rate_limit, bool b_blocked /*= true*/,
				 bool is_rexmit /*= false*/, int flags /*= 0*/,
				 socket_fd_api* sock /*= 0*/, tx_call_t call_type /*= 0*/)
{
	NOT_IN_USE(is_rexmit);

	ssize_t ret_val = 0;

	dst_udp_logdbg("In slow send");

	prepare_to_send(rate_limit, false);

	if (m_b_force_os || !m_b_is_offloaded) {
		struct sockaddr_in to_saddr;
		to_saddr.sin_port = m_dst_port;
		to_saddr.sin_addr.s_addr = m_dst_ip.get_in_addr();
		to_saddr.sin_family = AF_INET;
		dst_udp_logdbg("Calling to tx_os");
		ret_val = sock->tx_os(call_type, p_iov, sz_iov, flags, (const struct sockaddr*)&to_saddr, sizeof(struct sockaddr_in));
	}
	else {
		if (!is_valid()) { // That means that the neigh is not resolved yet
			ret_val = pass_buff_to_neigh(p_iov, sz_iov);
		}
		else {
			ret_val = fast_send(p_iov, sz_iov, is_dummy, b_blocked);
		}
	}

	return ret_val;
}

void dst_entry_udp::init_sge()
{
	m_sge[0].length = m_header.m_total_hdr_len;
	m_sge[0].addr = m_header.m_actual_hdr_addr;
}

ssize_t dst_entry_udp::pass_buff_to_neigh(const iovec *p_iov, size_t & sz_iov, uint16_t packet_id)
{
	m_header_neigh.init();
	m_header_neigh.configure_udp_header(m_dst_port, m_src_port);

	packet_id = (m_sysvar_thread_mode > THREAD_MODE_SINGLE) ?
						atomic_fetch_and_inc(&m_a_tx_ip_id) :
						m_n_tx_ip_id++;
	packet_id = htons(packet_id);

	return(dst_entry::pass_buff_to_neigh(p_iov, sz_iov, packet_id));
}
