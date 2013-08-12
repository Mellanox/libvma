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


#ifndef ARP_H
#define ARP_H

#include <sys/types.h>
#include <sys/socket.h>
#include "vma/util/vtypes.h"

struct __attribute__ ((packed)) eth_arp_hdr
{
	uint16_t 	m_hwtype;
	uint16_t 	m_proto;
	uint8_t  	m_hwlen;
	uint8_t  	m_protolen;
	uint16_t 	m_opcode;
	uint8_t 	m_shwaddr[ETH_ALEN];
	uint32_t 	m_sipaddr;
	uint8_t 	m_dhwaddr[ETH_ALEN];
	uint32_t 	m_dipaddr;
};

void set_eth_arp_hdr(eth_arp_hdr* p_arph, in_addr_t ipsrc_addr, in_addr_t ipdst_addr, const uint8_t* hwsrc_addr, const uint8_t* hwdst_addr);

struct __attribute__ ((packed)) ib_arp_hdr
{
	uint16_t 	m_hwtype;
	uint16_t 	m_proto;
	uint8_t  	m_hwlen;
	uint8_t  	m_protolen;
	uint16_t 	m_opcode;
	uint8_t 	m_shwaddr[IPOIB_HW_ADDR_LEN];
	uint32_t 	m_sipaddr;
	uint8_t 	m_dhwaddr[IPOIB_HW_ADDR_LEN];
	uint32_t 	m_dipaddr;
};

void set_ib_arp_hdr(ib_arp_hdr* p_arph, in_addr_t ipsrc_addr, in_addr_t ipdst_addr, const uint8_t* hwsrc_addr, const uint8_t* hwdst_addr);


#endif
