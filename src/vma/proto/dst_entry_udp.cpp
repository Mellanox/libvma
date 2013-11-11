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


#include "dst_entry_udp.h"
#include "vma/util/utils.h"
#include "vma/util/bullseye.h"

#define MODULE_NAME             "dst_udp"

#define dst_udp_logpanic           __log_panic
#define dst_udp_logerr             __log_err
#define dst_udp_logwarn            __log_warn
#define dst_udp_loginfo            __log_info
#define dst_udp_logdbg             __log_info_dbg
#define dst_udp_logfunc            __log_info_func
#define dst_udp_logfuncall         __log_info_funcall


dst_entry_udp::dst_entry_udp(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, int owner_fd):
	dst_entry(dst_ip, dst_port, src_port, owner_fd)
{
	dst_udp_logdbg("%s", to_str().c_str());
	atomic_set(&m_a_tx_ip_id, 0);
	m_n_tx_ip_id = 0;;
}

dst_entry_udp::~dst_entry_udp()
{
	dst_udp_logdbg("%s", to_str().c_str());
}

transport_t dst_entry_udp::get_transport(sockaddr_in to)
{
	return  __vma_match_udp_sender(TRANS_VMA, mce_sys.app_id, (sockaddr *)(&to), sizeof to);
}

//The following function supposed to be called under m_lock
void dst_entry_udp::configure_headers()
{
	m_header.init();
	m_header.configure_udp_header(m_dst_port, m_src_port);
	dst_entry::configure_headers();
}

ssize_t dst_entry_udp::fast_send(const iovec* p_iov, const ssize_t sz_iov, bool b_blocked /*=true*/, bool is_rexmit /*=false*/, bool dont_inline /*=false*/)
{
	NOT_IN_USE(is_rexmit);

	tx_packet_template_t *p_pkt;
	mem_buf_desc_t* p_mem_buf_desc = NULL, *tmp;
	uint16_t packet_id = 0;
	bool b_need_to_fragment;

	// Calc user data payload size
	ssize_t sz_data_payload = 0;
	for (ssize_t i = 0; i < sz_iov; i++)
		sz_data_payload += p_iov[i].iov_len;

	if (sz_data_payload > 65536) {
		dst_udp_logfunc("sz_data_payload=%d, to_port=%d, local_port=%d, b_blocked=%s", sz_data_payload, ntohs(m_dst_port), ntohs(m_src_port), b_blocked?"true":"false");
		dst_udp_logfunc("sz_data_payload=%d exceeds max of 64KB", sz_data_payload);
		errno = EMSGSIZE;
		return -1;
	}

	// Calc udp payload size
	size_t sz_udp_payload = sz_data_payload + sizeof(struct udphdr);

	if (!dont_inline && (sz_iov == 1 && (sz_data_payload + m_header.m_total_hdr_len) < m_max_inline)) {
		m_p_send_wqe = &m_inline_send_wqe;

		//m_sge[0].addr  already points to the header
		//so we just need to update the payload addr + len
		m_sge[1].length = p_iov[0].iov_len;
		m_sge[1].addr = (uintptr_t)p_iov[0].iov_base;

		m_header.m_header.hdr.m_udp_hdr.len = htons((uint16_t)sz_udp_payload);
		m_header.m_header.hdr.m_ip_hdr.tot_len = htons(IPV4_HDR_LEN + sz_udp_payload);

		// Get a bunch of tx buf descriptor and data buffers
		if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
			m_p_tx_mem_buf_desc_list = m_p_ring->mem_buf_tx_get(b_blocked, 8);
		}
		p_mem_buf_desc = m_p_tx_mem_buf_desc_list;

		if (unlikely(m_p_tx_mem_buf_desc_list == NULL)) {
			if (b_blocked) {
				dst_udp_logdbg("Error when blocking for next tx buffer (errno=%d %m)", errno);
			}
			else {
				dst_udp_logfunc("Packet dropped. NonBlocked call but not enough tx buffers. Returning OK");
				if (!mce_sys.tx_nonblocked_eagains) return sz_data_payload;
			}
			errno = EAGAIN;
			return -1;
		}
		else {
			m_p_tx_mem_buf_desc_list = m_p_tx_mem_buf_desc_list->p_next_desc;
		}

		m_inline_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;
		m_p_ring->send_ring_buffer(m_p_send_wqe, b_blocked);
	}
	else {
		// Find number of ip fragments (-> packets, buffers, buffer descs...)
		int n_num_frags = 1;
		b_need_to_fragment = false;
		m_p_send_wqe = &m_not_inline_send_wqe;

		// Usually max inline < MTU!
		if (sz_udp_payload > MAX_IP_PAYLOAD_SZ) {
			b_need_to_fragment = true;
			n_num_frags = (sz_udp_payload + MAX_IP_PAYLOAD_SZ - 1) / MAX_IP_PAYLOAD_SZ;
			packet_id = (mce_sys.thread_mode > THREAD_MODE_SINGLE) ?
					atomic_fetch_and_inc(&m_a_tx_ip_id) :
					m_n_tx_ip_id++;
			packet_id = htons(packet_id);
		}

		dst_udp_logfunc("udp info: payload_sz=%d, frags=%d, scr_port=%d, dst_port=%d, blocked=%s, ", sz_data_payload, n_num_frags, ntohs(m_header.m_header.hdr.m_udp_hdr.source), ntohs(m_dst_port), b_blocked?"true":"false");

		// Get all needed tx buf descriptor and data buffers
		p_mem_buf_desc = m_p_ring->mem_buf_tx_get(b_blocked, n_num_frags);

		if (unlikely(p_mem_buf_desc == NULL)) {
			if (b_blocked) {
				dst_udp_logdbg("Error when blocking for next tx buffer (errno=%d %m)", errno);
			}
			else {
				dst_udp_logfunc("Packet dropped. NonBlocked call but not enough tx buffers. Returning OK");
				if (!mce_sys.tx_nonblocked_eagains) return sz_data_payload;
			}
			errno = EAGAIN;
			return -1;
		}

		// Int for counting offset inside the ip datagram payload
		uint32_t n_ip_frag_offset = 0;
		size_t sz_user_data_offset = 0;

		while (n_num_frags--) {
			// Calc this ip datagram fragment size (include any udp header)
			size_t sz_ip_frag = min(MAX_IP_PAYLOAD_SZ, (sz_udp_payload - n_ip_frag_offset));
			size_t sz_user_data_to_copy = sz_ip_frag;
			size_t hdr_len = m_header.m_transport_header_len + IPV4_HDR_LEN; // Add count of L2 (ipoib or mac) header length

			if (mce_sys.tx_prefetch_bytes) {
				prefetch_range(p_mem_buf_desc->p_buffer + m_header.m_transport_header_tx_offset,
						min(sz_ip_frag, (size_t)mce_sys.tx_prefetch_bytes));
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
			p_pkt->hdr.m_ip_hdr.tot_len = htons(IPV4_HDR_LEN + sz_ip_frag);

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

			if (b_need_to_fragment) {
				dst_udp_logfunc("ip fragmentation detected, using SW checksum calculation");
				p_pkt->hdr.m_ip_hdr.check = 0;
				p_pkt->hdr.m_ip_hdr.check = csum((unsigned short*)&p_pkt->hdr.m_ip_hdr, IPV4_HDR_LEN_WORDS * 2);
				m_p_send_wqe_handler->disable_hw_csum(m_not_inline_send_wqe);
			} else {
				dst_udp_logfunc("using HW checksum calculation");
				m_p_send_wqe_handler->enable_hw_csum(m_not_inline_send_wqe);
			}


			m_sge[1].addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)m_header.m_transport_header_tx_offset);
			m_sge[1].length = sz_user_data_to_copy + hdr_len;
			m_not_inline_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;

			dst_udp_logfunc("%s packet_sz=%d, payload_sz=%d, ip_offset=%d id=%d", m_header.to_str().c_str(),
					m_sge[1].length - m_header.m_transport_header_len, sz_user_data_to_copy,
					n_ip_frag_offset, ntohs(packet_id));

			tmp = p_mem_buf_desc->p_next_desc;
			p_mem_buf_desc->p_next_desc = NULL;

			// We don't check the return valuse of post send when we reach the HW we consider that we completed our job
			m_p_ring->send_ring_buffer(m_p_send_wqe, b_blocked);

			p_mem_buf_desc = tmp;

			// Update ip frag offset position
			n_ip_frag_offset += sz_ip_frag;

			// Update user data start offset copy location
			sz_user_data_offset += sz_user_data_to_copy;

		} // while(n_num_frags)
	}

	// If all went well :) then return the user data count transmitted
	return sz_data_payload;
}

ssize_t dst_entry_udp::slow_send(const iovec* p_iov, size_t sz_iov, bool b_blocked /*= true*/, bool is_rexmit /*= false*/, int flags /*= 0*/, socket_fd_api* sock /*= 0*/, tx_call_t call_type /*= 0*/)
{
	NOT_IN_USE(is_rexmit);

	ssize_t ret_val = 0;

	dst_udp_logdbg("In slow send");

	prepare_to_send();

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
			ret_val = fast_send(p_iov, sz_iov, b_blocked);
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
	m_header.init();
	m_header.configure_udp_header(m_dst_port, m_src_port);

	packet_id = (mce_sys.thread_mode > THREAD_MODE_SINGLE) ?
						atomic_fetch_and_inc(&m_a_tx_ip_id) :
						m_n_tx_ip_id++;
	packet_id = htons(packet_id);

	return(dst_entry::pass_buff_to_neigh(p_iov, sz_iov, packet_id));
}
