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



#ifndef HEADER_H
#define HEADER_H

#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>

#include "util/vtypes.h"
#include "util/to_str.h"
#include "L2_address.h"
#include "util/sys_vars.h"

// We align the frame so IP header will be 4 bytes align
// And we align the L2 headers so IP header on both transport
// types will be at the same offset from buffer start
#define NET_IB_IP_ALIGN_SZ		16
#define NET_ETH_IP_ALIGN_SZ		 6
#define NET_ETH_VLAN_IP_ALIGN_SZ	 2

#define MAX_IP_PAYLOAD_SZ   	((mce_sys.mtu - sizeof(struct iphdr)) & ~0x7)

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

union __attribute__ ((packed)) l2_hdr_template_t  {
	ib_hdr_template_t	ib_hdr;
	eth_hdr_template_t	eth_hdr;
	vlan_eth_hdr_template_t	vlan_eth_hdr;
	uint32_t		words[];
};

struct __attribute__ ((packed)) tx_hdr_template_t  {		// Offeset  Size
	l2_hdr_template_t	m_l2_hdr;			//    0      20
	iphdr			m_ip_hdr;			//   20      20
	udphdr			m_udp_hdr;			//   40       8
};

union tx_packet_template_t {
	tx_hdr_template_t	hdr;
	uint32_t		words[];
};


class header: public tostr
{
public:
	header();
	header(const header &h);
	virtual ~header() {};


	void init();
	void configure_udp_header(uint16_t dest_port, uint16_t src_port);
	void configure_ip_header(uint8_t protocol, in_addr_t src_addr, in_addr_t dest_addr, uint8_t ttl = 64, uint8_t tos = 0, uint16_t packet_id = 0);
	void configure_ipoib_headers(uint32_t ipoib_header = IPOIB_HEADER);
	void set_mac_to_eth_header(const L2_address &src, const L2_address &dst, ethhdr &eth_header);
	void configure_eth_headers(const L2_address &src, const L2_address &dst, uint16_t encapsulated_proto = ETH_P_IP);
	void configure_vlan_eth_headers(const L2_address &src, const L2_address &dst, uint16_t tci, uint16_t encapsulated_proto = ETH_P_IP);

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
		p_hdr->words[0] = m_header.words[0]; // dummy(16) + l2(16) (mac / dummy)
		p_hdr->words[1] = m_header.words[1]; // l2 (32)            (mac / dummy)
		p_hdr->words[2] = m_header.words[2]; // l2 (32)            (mac / dummy)
		p_hdr->words[3] = m_header.words[3]; // l2 (32)            (mac / dummy)
		p_hdr->words[4] = m_header.words[4]; // l2 (32)            (mac / vlan / ipoib)
	}

	uintptr_t m_actual_hdr_addr;
	tx_packet_template_t m_header;
	size_t m_udp_header_len;
	size_t m_ip_header_len;
	size_t m_transport_header_len;
	size_t m_total_hdr_len;
	size_t m_aligned_l2_l3_len;
	size_t m_transport_header_tx_offset;
	transport_type_t m_transport_type;
};

#endif /* HEADER_H */
