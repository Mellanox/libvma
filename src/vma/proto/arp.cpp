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
