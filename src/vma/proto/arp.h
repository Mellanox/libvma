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
