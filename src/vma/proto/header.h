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



#ifndef HEADER_H
#define HEADER_H

#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>

#include "vma/util/vtypes.h"
#include "vma/util/to_str.h"
#include "L2_address.h"
#include "vma/util/sys_vars.h"

// We align the frame so IP header will be 4 bytes align
// And we align the L2 headers so IP header on both transport
// types will be at the same offset from buffer start
#define NET_IB_IP_ALIGN_SZ		16
#define NET_ETH_IP_ALIGN_SZ		 6
#define NET_ETH_VLAN_IP_ALIGN_SZ	 2
#define NET_ETH_VLAN_PCP_OFFSET	13

struct __attribute__ ((packed)) ib_hdr_template_t  {		// Offeset  Size
	char		m_alignment[NET_IB_IP_ALIGN_SZ];	//    0      16  = 16
	ipoibhdr	m_ipoib_hdr;				//   16       4  = 20
//	iphdr		m_ip_hdr;				//   20      20  = 40
};

struct __attribute__ ((packed)) eth_hdr_template_t  {		// Offeset  Size
	char		m_alignment[NET_ETH_IP_ALIGN_SZ];	//    0       6  =  6
	ethhdr		m_eth_hdr;				//    6      14  = 20
//	iphdr		m_ip_hdr;				//   20      20  = 40
};

struct __attribute__ ((packed)) vlan_eth_hdr_template_t  {	// Offeset  Size
	char		m_alignment[NET_ETH_VLAN_IP_ALIGN_SZ];	//    0       2  =  2
	ethhdr		m_eth_hdr;				//    2      14  = 16
	vlanhdr		m_vlan_hdr;				//   16       4  = 20
//	iphdr		m_ip_hdr;				//   20      20  = 40
};

union l2_hdr_template_t  {
	ib_hdr_template_t	ib_hdr;
	eth_hdr_template_t	eth_hdr;
	vlan_eth_hdr_template_t	vlan_eth_hdr;
};

struct __attribute__ ((packed, aligned)) tx_hdr_template_t  {		// Offeset  Size
	l2_hdr_template_t	m_l2_hdr;			//    0      20
	iphdr			m_ip_hdr;			//   20      20
	union {
	udphdr			m_udp_hdr;			//   40       8
	tcphdr			m_tcp_hdr;			//   40	     20
	};
};

union tx_packet_template_t {
	tx_hdr_template_t	hdr;
	uint32_t		words[15]; //change in tx_hdr_template_t size may require to modify this array size
};


class header: public tostr
{
public:
	header();
	header(const header &h);
	virtual ~header() {};


	void init();
	void configure_udp_header(uint16_t dest_port, uint16_t src_port);
	void configure_tcp_ports(uint16_t dest_port, uint16_t src_port);
	void configure_ip_header(uint8_t protocol, in_addr_t src_addr, in_addr_t dest_addr, uint8_t ttl = 64, uint8_t tos = 0, uint16_t packet_id = 0);
	void configure_ipoib_headers(uint32_t ipoib_header = IPOIB_HEADER);
	void set_mac_to_eth_header(const L2_address &src, const L2_address &dst, ethhdr &eth_header);
	void set_ip_ttl(uint8_t ttl);
	void set_ip_tos(uint8_t tos);
	void configure_eth_headers(const L2_address &src, const L2_address &dst, uint16_t encapsulated_proto = ETH_P_IP);
	void configure_vlan_eth_headers(const L2_address &src, const L2_address &dst, uint16_t tci, uint16_t encapsulated_proto = ETH_P_IP);
	bool set_vlan_pcp(uint8_t pcp);
	void update_actual_hdr_addr();

	inline void copy_l2_ip_hdr(tx_packet_template_t *p_hdr)
	{
		// copy words every time, to optimize for speed
		p_hdr->words[0] = m_header.words[0]; // dummy(16) + l2(16) (mac / dummy)
		p_hdr->words[1] = m_header.words[1]; // l2 (32)            (mac / dummy)
		p_hdr->words[2] = m_header.words[2]; // l2 (32)            (mac / dummy)
		p_hdr->words[3] = m_header.words[3]; // l2 (32)            (mac / dummy)
		p_hdr->words[4] = m_header.words[4]; // l2 (32)            (mac / vlan / ipoib)
		p_hdr->words[5] = m_header.words[5]; // IP-> ver(4) + hdrlen(4) + tos(8) + totlen(16)
		p_hdr->words[6] = m_header.words[6]; // IP-> id(16) + frag(16)
		p_hdr->words[7] = m_header.words[7]; // IP-> ttl(8) + protocol(8) + checksum(16)
		p_hdr->words[8] = m_header.words[8]; // IP-> saddr(32)
		p_hdr->words[9] = m_header.words[9]; // IP-> daddr(32)
	}

	inline void copy_l2_ip_udp_hdr(tx_packet_template_t *p_hdr)
	{
		copy_l2_ip_hdr(p_hdr);
		p_hdr->words[10] = m_header.words[10]; // UDP-> sport(16) + dst_port(16)
		p_hdr->words[11] = m_header.words[11]; // UDP-> len(16) + check(16)
	}

	inline void copy_l2_hdr(tx_packet_template_t *p_hdr)
	{
		uint32_t *to_words   = p_hdr->words;
		uint32_t *from_words = m_header.words;
		to_words[0] = from_words[0]; // dummy(16) + l2(16) (mac / dummy)
		to_words[1] = from_words[1]; // l2 (32)            (mac / dummy)
		to_words[2] = from_words[2]; // l2 (32)            (mac / dummy)
		to_words[3] = from_words[3]; // l2 (32)            (mac / dummy)
		to_words[4] = from_words[4]; // l2 (32)            (mac / vlan / ipoib)
	}

	uintptr_t m_actual_hdr_addr;
	tx_packet_template_t m_header;
	uint16_t m_ip_header_len;
	uint16_t m_transport_header_len;
	uint16_t m_total_hdr_len;
	uint16_t m_aligned_l2_l3_len;
	uint16_t m_transport_header_tx_offset;
	bool m_is_vlan_enabled;
	transport_type_t m_transport_type;
};

#endif /* HEADER_H */
