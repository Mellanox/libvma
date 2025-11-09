/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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

#endif
