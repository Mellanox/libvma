/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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
#include "vma/dev/rfs_uc_tcp_gro.h"
#include "vma/dev/gro_mgr.h"
#include "vma/dev/ring_simple.h"
#include "vma/proto/route_rule_table_key.h"

#define MODULE_NAME 		"rfs_uc_tcp_gro"

#define IP_H_LEN_NO_OPTIONS 5
#define TCP_H_LEN_NO_OPTIONS 5
#define TCP_H_LEN_TIMESTAMP 8


rfs_uc_tcp_gro::rfs_uc_tcp_gro(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter* rule_filter, uint32_t flow_tag_id) :
	rfs_uc(flow_spec_5t, p_ring, rule_filter, flow_tag_id),
	m_b_active(false), m_b_reserved(false)
{
	ring_simple* p_check_ring = dynamic_cast<ring_simple*>(p_ring);

	if (!p_check_ring) {
		rfs_logpanic("Incompatible ring type");
	}

	m_p_gro_mgr = &(p_check_ring->m_gro_mgr);
	m_n_buf_max = m_p_gro_mgr->get_buf_max();
	uint32_t mtu = p_check_ring->get_mtu();
	m_n_byte_max = m_p_gro_mgr->get_byte_max() - mtu;
	memset(&m_gro_desc, 0, sizeof(m_gro_desc));
}

bool rfs_uc_tcp_gro::rx_dispatch_packet(mem_buf_desc_t* p_rx_pkt_mem_buf_desc_info, void* pv_fd_ready_array /* = NULL */)
{
	struct iphdr* p_ip_h = p_rx_pkt_mem_buf_desc_info->rx.tcp.p_ip_h;
	struct tcphdr* p_tcp_h = p_rx_pkt_mem_buf_desc_info->rx.tcp.p_tcp_h;

	if (!m_b_active) {
		if (!m_b_reserved && m_p_gro_mgr->is_stream_max()) {
			goto out;
		}
	}

	if (!tcp_ip_check(p_rx_pkt_mem_buf_desc_info, p_ip_h, p_tcp_h)) {
		if (m_b_active) {
			flush_gro_desc(pv_fd_ready_array);
		}
		goto out;
	}

	if (!m_b_active) {
		if (!m_b_reserved) {
			m_b_reserved = m_p_gro_mgr->reserve_stream(this);
		}
		init_gro_desc(p_rx_pkt_mem_buf_desc_info, p_ip_h, p_tcp_h);
		m_b_active = true;
	} else {
		if (ntohl(p_tcp_h->seq) != m_gro_desc.next_seq) {
			flush_gro_desc(pv_fd_ready_array);
			goto out;
		}

		if (!timestamp_check(p_tcp_h)) {
			flush_gro_desc(pv_fd_ready_array);
			goto out;
		}

		add_packet(p_rx_pkt_mem_buf_desc_info, p_ip_h, p_tcp_h);
	}

	if (m_gro_desc.buf_count >= m_n_buf_max || m_gro_desc.ip_tot_len >= m_n_byte_max) {
		flush_gro_desc(pv_fd_ready_array);
	}

	return true;

out:
	return rfs_uc::rx_dispatch_packet(p_rx_pkt_mem_buf_desc_info, pv_fd_ready_array);
}

void rfs_uc_tcp_gro::add_packet(mem_buf_desc_t* mem_buf_desc, struct iphdr* p_ip_h, tcphdr* p_tcp_h)
{
	m_gro_desc.buf_count++;
	m_gro_desc.ip_tot_len += mem_buf_desc->rx.sz_payload;
	m_gro_desc.next_seq += mem_buf_desc->rx.sz_payload;
	m_gro_desc.wnd = p_tcp_h->window;
	m_gro_desc.ack = p_tcp_h->ack_seq;

	uint32_t* topt;
	if (m_gro_desc.ts_present) {
		topt = (uint32_t *) (p_tcp_h + 1);
		m_gro_desc.tsecr = *(topt + 2);
	}

	mem_buf_desc->reset_ref_count();

	mem_buf_desc->lwip_pbuf.pbuf.flags = PBUF_FLAG_IS_CUSTOM;
	mem_buf_desc->lwip_pbuf.pbuf.len = mem_buf_desc->lwip_pbuf.pbuf.tot_len = mem_buf_desc->rx.sz_payload;
	mem_buf_desc->lwip_pbuf.pbuf.ref = 1;
	mem_buf_desc->lwip_pbuf.pbuf.type = PBUF_REF;
	mem_buf_desc->lwip_pbuf.pbuf.next = NULL;
	mem_buf_desc->lwip_pbuf.pbuf.payload = (u8_t *)mem_buf_desc->p_buffer + mem_buf_desc->rx.tcp.n_transport_header_len + ntohs(p_ip_h->tot_len) - mem_buf_desc->rx.sz_payload;


	m_gro_desc.p_last->lwip_pbuf.pbuf.next = &(mem_buf_desc->lwip_pbuf.pbuf);
	m_gro_desc.p_last->p_next_desc = NULL;
	mem_buf_desc->p_prev_desc = m_gro_desc.p_last;
	m_gro_desc.p_last = mem_buf_desc;
}

void rfs_uc_tcp_gro::flush(void* pv_fd_ready_array)
{
	flush_gro_desc(pv_fd_ready_array);
	m_b_reserved = false;
}

struct __attribute__((packed)) tcphdr_ts
{
	tcphdr p_tcp_h;
	uint32_t popts[3];
};

void rfs_uc_tcp_gro::flush_gro_desc(void* pv_fd_ready_array)
{
	ring_simple* p_ring = dynamic_cast<ring_simple*>(m_p_ring);

	if (!p_ring) {
		rfs_logpanic("Incompatible ring type");
	}

	if (!m_b_active) return;

	if (m_gro_desc.buf_count > 1) {
		m_gro_desc.p_ip_h->tot_len = htons(m_gro_desc.ip_tot_len);
		m_gro_desc.p_tcp_h->ack_seq = m_gro_desc.ack;
		m_gro_desc.p_tcp_h->window = m_gro_desc.wnd;

		if (m_gro_desc.ts_present) {
			tcphdr_ts* p_tcp_ts_h = (tcphdr_ts*) m_gro_desc.p_tcp_h;
			p_tcp_ts_h->popts[2] = m_gro_desc.tsecr;
		}

		m_gro_desc.p_first->rx.tcp.gro = 1;

		m_gro_desc.p_first->lwip_pbuf.pbuf.flags = PBUF_FLAG_IS_CUSTOM;
		m_gro_desc.p_first->lwip_pbuf.pbuf.tot_len = m_gro_desc.p_first->lwip_pbuf.pbuf.len = (m_gro_desc.p_first->sz_data - m_gro_desc.p_first->rx.tcp.n_transport_header_len);
		m_gro_desc.p_first->lwip_pbuf.pbuf.ref = 1;
		m_gro_desc.p_first->lwip_pbuf.pbuf.type = PBUF_REF;
		m_gro_desc.p_first->lwip_pbuf.pbuf.payload = (u8_t *)(m_gro_desc.p_first->p_buffer + m_gro_desc.p_first->rx.tcp.n_transport_header_len);
		m_gro_desc.p_first->rx.is_vma_thr = m_gro_desc.p_last->rx.is_vma_thr;

		for (mem_buf_desc_t* p_desc = m_gro_desc.p_last; p_desc != m_gro_desc.p_first; p_desc = p_desc->p_prev_desc) {
			p_desc->p_prev_desc->lwip_pbuf.pbuf.tot_len += p_desc->lwip_pbuf.pbuf.tot_len;
		}
	}

	__log_func("Rx LRO TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u, num_bufs=%u",
					ntohs(m_gro_desc.p_tcp_h->source), ntohs(m_gro_desc.p_tcp_h->dest),
					m_gro_desc.p_tcp_h->urg?"U":"", m_gro_desc.p_tcp_h->ack?"A":"", m_gro_desc.p_tcp_h->psh?"P":"",
					m_gro_desc.p_tcp_h->rst?"R":"", m_gro_desc.p_tcp_h->syn?"S":"", m_gro_desc.p_tcp_h->fin?"F":"",
					ntohl(m_gro_desc.p_tcp_h->seq), ntohl(m_gro_desc.p_tcp_h->ack_seq), ntohs(m_gro_desc.p_tcp_h->window),
					m_gro_desc.ip_tot_len - 40, m_gro_desc.buf_count);

	if (!rfs_uc::rx_dispatch_packet(m_gro_desc.p_first, pv_fd_ready_array)) {
		p_ring->reclaim_recv_buffers_no_lock(m_gro_desc.p_first);
	}

	m_b_active = false;
}

void rfs_uc_tcp_gro::init_gro_desc(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h)
{
	m_gro_desc.p_first = m_gro_desc.p_last = mem_buf_desc;
	m_gro_desc.buf_count = 1;
	m_gro_desc.p_ip_h = p_ip_h;
	m_gro_desc.p_tcp_h = p_tcp_h;
	m_gro_desc.ip_tot_len = ntohs(p_ip_h->tot_len);
	m_gro_desc.ack = p_tcp_h->ack_seq;
	m_gro_desc.next_seq = ntohl(p_tcp_h->seq) + mem_buf_desc->rx.sz_payload;
	m_gro_desc.wnd = p_tcp_h->window;
	m_gro_desc.ts_present = 0;
	if (p_tcp_h->doff == TCP_H_LEN_TIMESTAMP) {
		uint32_t* topt = (uint32_t*)(p_tcp_h + 1);
		m_gro_desc.ts_present = 1;
		m_gro_desc.tsval = *(topt+1);
		m_gro_desc.tsecr = *(topt+2);
	}
}

bool rfs_uc_tcp_gro::tcp_ip_check(mem_buf_desc_t* mem_buf_desc, iphdr* p_ip_h, tcphdr* p_tcp_h)
{

	if (mem_buf_desc->rx.sz_payload == 0) {
		return false;
	}

	if (p_ip_h->ihl != IP_H_LEN_NO_OPTIONS) {
		return false;
	}

	if (p_tcp_h->urg || !p_tcp_h->ack || p_tcp_h->rst || p_tcp_h->syn || p_tcp_h->fin) {
		return false;
	}

	if (p_tcp_h->doff != TCP_H_LEN_NO_OPTIONS && p_tcp_h->doff != TCP_H_LEN_TIMESTAMP) {
		return false;
	}

	return true;
}

bool rfs_uc_tcp_gro::timestamp_check(tcphdr* p_tcp_h)
{
	if (p_tcp_h->doff == TCP_H_LEN_TIMESTAMP) {
		uint32_t* topt = (uint32_t*)(p_tcp_h + 1);
		if (*topt != htonl((TCPOPT_NOP << 24) |
				(TCPOPT_NOP << 16) |
				(TCPOPT_TIMESTAMP << 8) |
				TCPOLEN_TIMESTAMP)) {
			return false;
		}

		topt++;

		if (ntohl(*topt) < ntohl(m_gro_desc.tsval)) {

		}

		topt++;

		if (*topt == 0) {
			return false;
		}

	}
	return true;
}
