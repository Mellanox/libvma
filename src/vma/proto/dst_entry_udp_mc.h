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


#ifndef DST_ENTRY_UDP_MC_H
#define DST_ENTRY_UDP_MC_H

#include "vma/proto/dst_entry_udp.h"

class dst_entry_udp_mc : public dst_entry_udp
{
public:
	dst_entry_udp_mc(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port,
			in_addr_t mc_tx_if_ip, bool mc_b_loopback, socket_data &sock_data,
			resource_allocation_key &ring_alloc_logic);
	virtual ~dst_entry_udp_mc();

	virtual bool 	conf_l2_hdr_and_snd_wqe_ib();

protected:
	ip_address 	m_mc_tx_if_ip;
	bool 		m_b_mc_loopback_enabled;

	virtual void	set_src_addr();
	virtual bool 	resolve_net_dev(bool is_connect=false);
};

#endif /* DST_ENTRY_UDP_MC_H */
