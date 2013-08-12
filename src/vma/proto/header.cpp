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


#include "header.h"


void header::init()
{
	memset(&m_header, 0, sizeof(tx_packet_template_t));
	m_ip_header_len = 0;
	m_transport_header_len = 0;
	m_udp_header_len = 0;
	m_total_hdr_len = 0;
	m_aligned_l2_l3_len = 40;
}

header::header() : m_actual_hdr_addr(0), m_transport_header_tx_offset(0), m_transport_type(VMA_TRANSPORT_UNKNOWN)
{
	init();
}

header::header(const header &h): tostr()
{
	m_header = h.m_header;
	m_udp_header_len = h.m_udp_header_len;
	m_ip_header_len = h.m_ip_header_len;
	m_transport_header_len = h.m_transport_header_len;
	m_total_hdr_len = h.m_total_hdr_len;
	m_aligned_l2_l3_len = h.m_aligned_l2_l3_len;
	m_transport_header_tx_offset = h.m_transport_header_tx_offset;
	m_transport_type = h.m_transport_type;
	update_actual_hdr_addr();
}

void header::configure_udp_header(uint16_t dest_port, uint16_t src_port)
{
	udphdr *p_udp_hdr = &m_header.hdr.m_udp_hdr;

	memset(p_udp_hdr, 0 , (sizeof(struct udphdr)));

	p_udp_hdr->dest = dest_port;
	p_udp_hdr->source = src_port;
	p_udp_hdr->check = 0;

	m_udp_header_len = sizeof(udphdr);
	m_total_hdr_len += m_udp_header_len;
}

void header::configure_ip_header(uint8_t protocol, in_addr_t src_addr, in_addr_t dest_addr, uint8_t ttl, uint8_t tos, uint16_t packet_id)
{
	iphdr* p_hdr = &m_header.hdr.m_ip_hdr;

	memset(p_hdr, 0 , (sizeof(struct iphdr)));

	// build ip header
	p_hdr->ihl = IPV4_HDR_LEN_WORDS; // 5 * 4 bytes (32 bit words) = 20 bytes = regular iph length with out any optionals
	p_hdr->version = IPV4_VERSION;
	p_hdr->protocol = protocol;
	p_hdr->saddr = src_addr;
	p_hdr->daddr = dest_addr;
	p_hdr->tos = tos;
	p_hdr->ttl = ttl;
	p_hdr->id = packet_id;

	m_ip_header_len = IPV4_HDR_LEN;
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

void header::configure_eth_headers(const L2_address &src, const L2_address &dst, uint16_t encapsulated_proto/*=ETH_P_IP*/)
{
	eth_hdr_template_t *p_eth_hdr = &m_header.hdr.m_l2_hdr.eth_hdr;
	p_eth_hdr->m_eth_hdr.h_proto = htons(encapsulated_proto);
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

	m_transport_header_tx_offset = sizeof(p_vlan_eth_hdr->m_alignment);
	m_transport_header_len += sizeof(p_vlan_eth_hdr->m_vlan_hdr);
	m_total_hdr_len += m_transport_header_len;
	update_actual_hdr_addr();
}

