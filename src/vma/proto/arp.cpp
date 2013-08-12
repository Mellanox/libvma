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


#include <netinet/in.h>
#include <linux/if_ether.h>
#include <string.h>
#include "vma/proto/arp.h"
#include "vma/util/vtypes.h"
#include <stdio.h>

/* ARP message types (opcodes) */
#define ARP_REQUEST 0x0001

#define HWTYPE_ETHERNET 	0x0001
#define HWTYPE_IB		0x0020
#define IPv4_ALEN 		0x04
#define ETHADDR_COPY(dst, src)  memcpy(dst, src, ETH_ALEN)
#define IBADDR_COPY(dst, src)   memcpy(dst, src, IPOIB_HW_ADDR_LEN)

void set_eth_arp_hdr(eth_arp_hdr *p_arph, in_addr_t ipsrc_addr, in_addr_t ipdst_addr, const uint8_t* hwsrc_addr, const uint8_t* hwdst_addr)
{
	p_arph->m_hwtype 	= htons(HWTYPE_ETHERNET);
	p_arph->m_proto 	= htons(ETH_P_IP);
	p_arph->m_hwlen		= ETH_ALEN;
	p_arph->m_protolen 	= IPv4_ALEN;
	p_arph->m_opcode	= htons(ARP_REQUEST);
	ETHADDR_COPY(p_arph->m_shwaddr, hwsrc_addr);
	p_arph->m_sipaddr	= ipsrc_addr;
	ETHADDR_COPY(p_arph->m_dhwaddr, hwdst_addr);
	p_arph->m_dipaddr	= ipdst_addr;
}

void set_ib_arp_hdr(ib_arp_hdr* p_arph, in_addr_t ipsrc_addr, in_addr_t ipdst_addr, const uint8_t* hwsrc_addr, const uint8_t* hwdst_addr)
{
	p_arph->m_hwtype 	= htons(HWTYPE_IB);
	p_arph->m_proto 	= htons(ETH_P_IP);
	p_arph->m_hwlen		= IPOIB_HW_ADDR_LEN;
	p_arph->m_protolen 	= IPv4_ALEN;
	p_arph->m_opcode	= htons(ARP_REQUEST);
	IBADDR_COPY(p_arph->m_shwaddr, hwsrc_addr);
	p_arph->m_sipaddr	= ipsrc_addr;
	if(hwdst_addr)
		IBADDR_COPY(p_arph->m_dhwaddr, hwdst_addr);
	p_arph->m_dipaddr	= ipdst_addr;
}
