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


#include "header.h"


void header::init()
{
	memset(&m_header, 0, sizeof(m_header));
	m_ip_header_len = 0;
	m_transport_header_len = 0;
	m_total_hdr_len = 0;
	m_aligned_l2_l3_len = 40;
	m_is_vlan_enabled = false;
}

header::header() :
	m_actual_hdr_addr(0),
	m_transport_header_tx_offset(0),
	m_is_vlan_enabled(false),
	m_transport_type(VMA_TRANSPORT_UNKNOWN)
{
	init();
}

header::header(const header &h): tostr()
{
	m_header = h.m_header;
	m_ip_header_len = h.m_ip_header_len;
	m_transport_header_len = h.m_transport_header_len;
	m_total_hdr_len = h.m_total_hdr_len;
	m_aligned_l2_l3_len = h.m_aligned_l2_l3_len;
	m_transport_header_tx_offset = h.m_transport_header_tx_offset;
	m_is_vlan_enabled = h.m_is_vlan_enabled;
	m_transport_type = h.m_transport_type;
	update_actual_hdr_addr();
}

void header::configure_udp_header(uint16_t dest_port, uint16_t src_port)
{
	udphdr *p_udp_hdr = &m_header.hdr.m_udp_hdr;

	memset(p_udp_hdr, 0 , (sizeof(*p_udp_hdr)));

	p_udp_hdr->dest = dest_port;
	p_udp_hdr->source = src_port;
	p_udp_hdr->check = 0;

	m_total_hdr_len += sizeof(udphdr);
}

void header::configure_tcp_ports(uint16_t dest_port, uint16_t src_port)
{
	tcphdr *p_tcp_hdr = &m_header.hdr.m_tcp_hdr;

	/* memset(p_tcp_hdr, 0 , (sizeof(*p_tcp_hdr))); */

	p_tcp_hdr->dest = dest_port;
	p_tcp_hdr->source = src_port;

	/* don't increase header len, as the tcp stack is not using these ports */
}

void header::configure_ip_header(uint8_t protocol, in_addr_t src_addr, in_addr_t dest_addr, uint8_t ttl, uint8_t tos, uint16_t packet_id)
{
	iphdr* p_hdr = &m_header.hdr.m_ip_hdr;

	memset(p_hdr, 0 , (sizeof(*p_hdr)));

	// build ip header
	p_hdr->ihl = IPV4_HDR_LEN_WITHOUT_OPTIONS / sizeof(uint32_t); // 5 * 4 bytes (32 bit words) = 20 bytes = regular iph length with out any optionals
	p_hdr->version = IPV4_VERSION;
	p_hdr->protocol = protocol;
	p_hdr->saddr = src_addr;
	p_hdr->daddr = dest_addr;
	p_hdr->tos = tos;
	p_hdr->ttl = ttl;
	p_hdr->id = packet_id;

	m_ip_header_len = IPV4_HDR_LEN_WITHOUT_OPTIONS;
	m_total_hdr_len += m_ip_header_len;
}

void header::configure_ipoib_headers(uint32_t ipoib_header /*=IPOIB_HEADER*/)
{
	ib_hdr_template_t *p_hdr = &m_header.hdr.m_l2_hdr.ib_hdr;
	m_transport_header_tx_offset = sizeof(p_hdr->m_alignment);
	m_transport_header_len = sizeof(p_hdr->m_ipoib_hdr);
	m_total_hdr_len += m_transport_header_len;
	p_hdr->m_ipoib_hdr.ipoib_header = htonl(ipoib_header);
	update_actual_hdr_addr();
}

void header::set_mac_to_eth_header(const L2_address &src, const L2_address &dst, ethhdr &eth_header)
{
	// copy source and destination mac address to eth header
	memcpy(eth_header.h_source, src.get_address(), src.get_addrlen());
	memcpy(eth_header.h_dest, dst.get_address(), dst.get_addrlen());
	// sets the size of 'm_eth_hdr' in the 'eth_hdr_template' struct
	m_transport_header_len = sizeof(eth_header);
}

void header::set_ip_ttl(uint8_t ttl)
{
	iphdr* p_hdr = &m_header.hdr.m_ip_hdr;

	p_hdr->ttl = ttl;
}

void header::set_ip_tos(uint8_t tos)
{
	iphdr* p_hdr = &m_header.hdr.m_ip_hdr;

	p_hdr->tos = tos;
}

void header::configure_eth_headers(const L2_address &src, const L2_address &dst, uint16_t encapsulated_proto/*=ETH_P_IP*/)
{
	eth_hdr_template_t *p_eth_hdr = &m_header.hdr.m_l2_hdr.eth_hdr;
	p_eth_hdr->m_eth_hdr.h_proto = htons(encapsulated_proto);
	m_is_vlan_enabled = false;
	set_mac_to_eth_header(src, dst, p_eth_hdr->m_eth_hdr);
	m_transport_header_tx_offset = sizeof(p_eth_hdr->m_alignment);
	m_total_hdr_len += m_transport_header_len;

	update_actual_hdr_addr();
}

void header::update_actual_hdr_addr()
{
	m_actual_hdr_addr = (uintptr_t)((((uint8_t*)(&m_header)) + (uint8_t)(m_transport_header_tx_offset)));
}

void header::configure_vlan_eth_headers(const L2_address &src, const L2_address &dst, uint16_t tos, uint16_t encapsulated_proto/*=ETH_P_IP*/)
{
	vlan_eth_hdr_template_t* p_vlan_eth_hdr = &m_header.hdr.m_l2_hdr.vlan_eth_hdr;
	set_mac_to_eth_header(src, dst, p_vlan_eth_hdr->m_eth_hdr);

	p_vlan_eth_hdr->m_vlan_hdr.h_vlan_TCI = htons(tos);
	p_vlan_eth_hdr->m_eth_hdr.h_proto = htons(ETH_P_8021Q);
	p_vlan_eth_hdr->m_vlan_hdr.h_vlan_encapsulated_proto = htons(encapsulated_proto);
	m_is_vlan_enabled = true;
	m_transport_header_tx_offset = sizeof(p_vlan_eth_hdr->m_alignment);
	m_transport_header_len += sizeof(p_vlan_eth_hdr->m_vlan_hdr);
	m_total_hdr_len += m_transport_header_len;
	update_actual_hdr_addr();
}


bool header::set_vlan_pcp(uint8_t pcp)
{
	if (!m_is_vlan_enabled) {
		return false;
	}
	vlan_eth_hdr_template_t* p_vlan_eth_hdr =
			&m_header.hdr.m_l2_hdr.vlan_eth_hdr;
	// zero old pcp and set new one
	uint16_t vlan_pcp = ((uint16_t)pcp << NET_ETH_VLAN_PCP_OFFSET) |
			(htons(p_vlan_eth_hdr->m_vlan_hdr.h_vlan_TCI) & 0x1fff);
	p_vlan_eth_hdr->m_vlan_hdr.h_vlan_TCI = htons(vlan_pcp);

	return true;
}
